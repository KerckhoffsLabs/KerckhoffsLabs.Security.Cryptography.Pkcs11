using System.Formats.Asn1;
using System.Security.Cryptography;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

// Sign / verify dispatch: HMAC (generic-secret key), asymmetric RSA/ECDSA, and PQC ML-DSA/SLH-DSA.
// PKCS#11 ECDSA signatures are raw r‖s — the BCL's default IEEE-P1363 format — so no conversion.
internal sealed partial class ManagedSoftToken
{
    private readonly Dictionary<ulong, SignOp> _signOps = [];
    private readonly Dictionary<ulong, SignOp> _verifyOps = [];

    /// <summary>When set, replaces what <c>C_Sign</c> returns — lets tests exercise a token whose
    /// signature or MAC is not the length the mechanism produces.</summary>
    public Func<byte[], byte[]>? SignatureOverride { get; set; }

    // PssHash: for CKM_RSA_PKCS_PSS, the hash its parameters name.
    private readonly record struct SignOp(ulong Mechanism, ulong Key, byte[] Context, HashAlgorithmName PssHash = default);

    protected override CKR C_SignInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key)
        => InitSignOp(_signOps, (ulong)session, ref mechanism, (ulong)key);

    protected override CKR C_VerifyInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key)
        => InitSignOp(_verifyOps, (ulong)session, ref mechanism, (ulong)key);

    private CKR InitSignOp(Dictionary<ulong, SignOp> store, ulong session, ref CK_MECHANISM mech, ulong key)
    {
        var m = (CKM)(ulong)mech.Mechanism;
        if (!_sessions.Contains(session)) return CKR.CKR_SESSION_HANDLE_INVALID;
        if (!IsHmac(m) && !IsAsymSign(m) && !IsPqcSign(m)) return CKR.CKR_MECHANISM_INVALID;
        if (!_objects.ContainsKey(key)) return CKR.CKR_KEY_HANDLE_INVALID;

        byte[] context = IsPqcSign(m) ? ReadPqcContext(ref mech) : [];
        HashAlgorithmName pssHash = default;
        if (m == CKM.CKM_RSA_PKCS_PSS && !TryReadPssHash(ref mech, out pssHash))
            return CKR.CKR_MECHANISM_PARAM_INVALID;
        store[session] = new SignOp((ulong)m, key, context, pssHash);
        return CKR.CKR_OK;
    }

    // The BCL's PSS uses MGF1 with the message hash and a salt of the hash's length, so other parameters
    // cannot be honoured and are refused.
    private static bool TryReadPssHash(ref CK_MECHANISM mech, out HashAlgorithmName hash)
    {
        hash = default;
        if (mech.Parameter == IntPtr.Zero) return false;
        var p = UnmanagedMemory.Read<CK_RSA_PKCS_PSS_PARAMS>(mech.Parameter);
        (hash, CKG mgf, int length) = (CKM)(ulong)p.HashAlg switch
        {
            CKM.CKM_SHA_1 => (HashAlgorithmName.SHA1, CKG.CKG_MGF1_SHA1, 20),
            CKM.CKM_SHA256 => (HashAlgorithmName.SHA256, CKG.CKG_MGF1_SHA256, 32),
            CKM.CKM_SHA384 => (HashAlgorithmName.SHA384, CKG.CKG_MGF1_SHA384, 48),
            CKM.CKM_SHA512 => (HashAlgorithmName.SHA512, CKG.CKG_MGF1_SHA512, 64),
            _ => (default, default, -1),
        };
        return length > 0 && (CKG)(ulong)p.Mgf == mgf && (ulong)p.Len == (ulong)length;
    }

    private static byte[] ReadPqcContext(ref CK_MECHANISM mech)
    {
        if (mech.Parameter == IntPtr.Zero) return [];
        var p = UnmanagedMemory.Read<CK_SIGN_ADDITIONAL_CONTEXT>(mech.Parameter);
        return p.Context != IntPtr.Zero && (int)p.ContextLen > 0
            ? UnmanagedMemory.Read(p.Context, (int)p.ContextLen) : [];
    }

    protected override CKR C_Sign(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> signature, ref NativeCULong signatureLen)
    {
        signatureLen = (NativeCULong)0;
        if (!_signOps.TryGetValue((ulong)session, out var op)) return CKR.CKR_OPERATION_NOT_INITIALIZED;

        byte[] input = data.ToArray();
        var m = (CKM)op.Mechanism;
        byte[] sig;
        try
        {
            if (IsHmac(m))
            {
                if (!_objects[op.Key].TryGetValue((ulong)CKA.CKA_VALUE, out var keyVal)) return CKR.CKR_KEY_HANDLE_INVALID;
                sig = ComputeHmac(m, keyVal, input);
            }
            else
            {
                if (!_asymKeys.TryGetValue(op.Key, out var alg)) return CKR.CKR_KEY_HANDLE_INVALID;
                sig = IsPqcSign(m) ? PqcSign(m, alg, input, op.Context)
                    : IsRawRsaSign(m) ? RawRsaSign(m, (RSA)alg, input, op.PssHash)
                    : AsymSign(m, (AsymmetricAlgorithm)alg, input);
            }
        }
        catch (CryptographicException) { _signOps.Remove((ulong)session); return CKR.CKR_FUNCTION_FAILED; }

        if (SignatureOverride is { } replace) sig = replace(sig);
        if (signature.IsNull) { signatureLen = (NativeCULong)(ulong)sig.Length; return CKR.CKR_OK; }
        if (signature.Span.Length < sig.Length) { signatureLen = (NativeCULong)(ulong)sig.Length; return CKR.CKR_BUFFER_TOO_SMALL; }

        sig.AsSpan(0, sig.Length).CopyTo(signature.Span);
        signatureLen = (NativeCULong)(ulong)sig.Length;
        _signOps.Remove((ulong)session);
        return CKR.CKR_OK;
    }

    protected override CKR C_Verify(NativeCULong session, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        if (!_verifyOps.TryGetValue((ulong)session, out var op)) return CKR.CKR_OPERATION_NOT_INITIALIZED;
        _verifyOps.Remove((ulong)session);

        byte[] input = data.ToArray();
        byte[] sig = signature.ToArray();
        var m = (CKM)op.Mechanism;

        bool ok;
        try
        {
            if (IsHmac(m))
            {
                if (!_objects[op.Key].TryGetValue((ulong)CKA.CKA_VALUE, out var keyVal)) return CKR.CKR_KEY_HANDLE_INVALID;
                ok = CryptographicOperations.FixedTimeEquals(ComputeHmac(m, keyVal, input), sig);
            }
            else
            {
                if (!_asymKeys.TryGetValue(op.Key, out var alg)) return CKR.CKR_KEY_HANDLE_INVALID;
                ok = IsPqcSign(m) ? PqcVerify(m, alg, input, sig, op.Context)
                    : IsRawRsaSign(m) ? RawRsaVerify(m, (RSA)alg, input, sig, op.PssHash)
                    : AsymVerify(m, (AsymmetricAlgorithm)alg, input, sig);
            }
        }
        catch (CryptographicException) { return CKR.CKR_SIGNATURE_INVALID; }

        return ok ? CKR.CKR_OK : CKR.CKR_SIGNATURE_INVALID;
    }

    // === RSA / ECDSA classification + BCL dispatch =======================

    private static bool IsEcdsaSign(CKM m) => m is
        CKM.CKM_ECDSA or CKM.CKM_ECDSA_SHA1 or CKM.CKM_ECDSA_SHA256 or CKM.CKM_ECDSA_SHA384 or CKM.CKM_ECDSA_SHA512;

    private static bool IsRsaSign(CKM m) => m is
        CKM.CKM_SHA1_RSA_PKCS or CKM.CKM_SHA256_RSA_PKCS or CKM.CKM_SHA384_RSA_PKCS or CKM.CKM_SHA512_RSA_PKCS
        or CKM.CKM_SHA1_RSA_PKCS_PSS or CKM.CKM_SHA256_RSA_PKCS_PSS or CKM.CKM_SHA384_RSA_PKCS_PSS or CKM.CKM_SHA512_RSA_PKCS_PSS;

    private static bool IsDsaSign(CKM m) => m is
        CKM.CKM_DSA or CKM.CKM_DSA_SHA1 or CKM.CKM_DSA_SHA256 or CKM.CKM_DSA_SHA384 or CKM.CKM_DSA_SHA512;

    private static bool IsRawRsaSign(CKM m) => m is CKM.CKM_RSA_PKCS or CKM.CKM_RSA_PKCS_PSS;

    private static bool IsAsymSign(CKM m) => IsEcdsaSign(m) || IsRsaSign(m) || IsDsaSign(m) || IsRawRsaSign(m);

    private static byte[] AsymSign(CKM m, AsymmetricAlgorithm alg, byte[] input) => m switch
    {
        CKM.CKM_ECDSA => ((ECDsa)alg).SignHash(input),
        CKM.CKM_ECDSA_SHA1 => ((ECDsa)alg).SignData(input, HashAlgorithmName.SHA1),
        CKM.CKM_ECDSA_SHA256 => ((ECDsa)alg).SignData(input, HashAlgorithmName.SHA256),
        CKM.CKM_ECDSA_SHA384 => ((ECDsa)alg).SignData(input, HashAlgorithmName.SHA384),
        CKM.CKM_ECDSA_SHA512 => ((ECDsa)alg).SignData(input, HashAlgorithmName.SHA512),
        CKM.CKM_DSA => ((DSA)alg).CreateSignature(input), // input is the prehash; IEEE-P1363 (r‖s)
        CKM.CKM_DSA_SHA1 => ((DSA)alg).SignData(input, HashAlgorithmName.SHA1),
        CKM.CKM_DSA_SHA256 => ((DSA)alg).SignData(input, HashAlgorithmName.SHA256),
        CKM.CKM_DSA_SHA384 => ((DSA)alg).SignData(input, HashAlgorithmName.SHA384),
        CKM.CKM_DSA_SHA512 => ((DSA)alg).SignData(input, HashAlgorithmName.SHA512),
        _ when IsRsaSign(m) => RsaSignData(m, (RSA)alg, input),
        _ => throw new CryptographicException($"ManagedSoftToken: unsupported sign mechanism {m}."),
    };

    private static bool AsymVerify(CKM m, AsymmetricAlgorithm alg, byte[] input, byte[] sig) => m switch
    {
        CKM.CKM_ECDSA => ((ECDsa)alg).VerifyHash(input, sig),
        CKM.CKM_ECDSA_SHA1 => ((ECDsa)alg).VerifyData(input, sig, HashAlgorithmName.SHA1),
        CKM.CKM_ECDSA_SHA256 => ((ECDsa)alg).VerifyData(input, sig, HashAlgorithmName.SHA256),
        CKM.CKM_ECDSA_SHA384 => ((ECDsa)alg).VerifyData(input, sig, HashAlgorithmName.SHA384),
        CKM.CKM_ECDSA_SHA512 => ((ECDsa)alg).VerifyData(input, sig, HashAlgorithmName.SHA512),
        CKM.CKM_DSA => ((DSA)alg).VerifySignature(input, sig),
        CKM.CKM_DSA_SHA1 => ((DSA)alg).VerifyData(input, sig, HashAlgorithmName.SHA1),
        CKM.CKM_DSA_SHA256 => ((DSA)alg).VerifyData(input, sig, HashAlgorithmName.SHA256),
        CKM.CKM_DSA_SHA384 => ((DSA)alg).VerifyData(input, sig, HashAlgorithmName.SHA384),
        CKM.CKM_DSA_SHA512 => ((DSA)alg).VerifyData(input, sig, HashAlgorithmName.SHA512),
        _ when IsRsaSign(m) => RsaVerifyData(m, (RSA)alg, input, sig),
        _ => throw new CryptographicException($"ManagedSoftToken: unsupported verify mechanism {m}."),
    };

    private static byte[] RsaSignData(CKM m, RSA rsa, byte[] data)
    {
        var (hash, padding) = RsaHashPadding(m);
        return rsa.SignData(data, hash, padding);
    }

    private static bool RsaVerifyData(CKM m, RSA rsa, byte[] data, byte[] sig)
    {
        var (hash, padding) = RsaHashPadding(m);
        return rsa.VerifyData(data, sig, hash, padding);
    }

    // Raw RSA signing over a caller-computed digest. CKM_RSA_PKCS signs a DER DigestInfo; the BCL signs a
    // digest only together with its hash, so the DigestInfo is read back into one, which gives the same
    // signature. A DigestInfo that does not parse fails like any other bad input.
    private static byte[] RawRsaSign(CKM m, RSA rsa, byte[] input, HashAlgorithmName pssHash)
    {
        if (m == CKM.CKM_RSA_PKCS_PSS)
            return rsa.SignHash(input, pssHash, RSASignaturePadding.Pss);
        var (hash, digest) = ReadDigestInfo(input);
        return rsa.SignHash(digest, hash, RSASignaturePadding.Pkcs1);
    }

    private static bool RawRsaVerify(CKM m, RSA rsa, byte[] input, byte[] sig, HashAlgorithmName pssHash)
    {
        if (m == CKM.CKM_RSA_PKCS_PSS)
            return rsa.VerifyHash(input, sig, pssHash, RSASignaturePadding.Pss);
        var (hash, digest) = ReadDigestInfo(input);
        return rsa.VerifyHash(digest, sig, hash, RSASignaturePadding.Pkcs1);
    }

    private static (HashAlgorithmName Hash, byte[] Digest) ReadDigestInfo(byte[] digestInfo)
    {
        try
        {
            var reader = new AsnReader(digestInfo, AsnEncodingRules.DER);
            AsnReader info = reader.ReadSequence();
            reader.ThrowIfNotEmpty();
            AsnReader algorithm = info.ReadSequence();
            HashAlgorithmName hash = algorithm.ReadObjectIdentifier() switch
            {
                "1.3.14.3.2.26" => HashAlgorithmName.SHA1,
                "2.16.840.1.101.3.4.2.1" => HashAlgorithmName.SHA256,
                "2.16.840.1.101.3.4.2.2" => HashAlgorithmName.SHA384,
                "2.16.840.1.101.3.4.2.3" => HashAlgorithmName.SHA512,
                var oid => throw new CryptographicException($"ManagedSoftToken: unsupported DigestInfo hash {oid}."),
            };
            algorithm.ReadNull();
            algorithm.ThrowIfNotEmpty();
            byte[] digest = info.ReadOctetString();
            info.ThrowIfNotEmpty();
            return (hash, digest);
        }
        catch (AsnContentException e)
        {
            throw new CryptographicException("ManagedSoftToken: malformed DigestInfo.", e);
        }
    }

    private static (HashAlgorithmName hash, RSASignaturePadding padding) RsaHashPadding(CKM m) => m switch
    {
        CKM.CKM_SHA1_RSA_PKCS => (HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1),
        CKM.CKM_SHA256_RSA_PKCS => (HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
        CKM.CKM_SHA384_RSA_PKCS => (HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
        CKM.CKM_SHA512_RSA_PKCS => (HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),
        CKM.CKM_SHA1_RSA_PKCS_PSS => (HashAlgorithmName.SHA1, RSASignaturePadding.Pss),
        CKM.CKM_SHA256_RSA_PKCS_PSS => (HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
        CKM.CKM_SHA384_RSA_PKCS_PSS => (HashAlgorithmName.SHA384, RSASignaturePadding.Pss),
        CKM.CKM_SHA512_RSA_PKCS_PSS => (HashAlgorithmName.SHA512, RSASignaturePadding.Pss),
        _ => throw new CryptographicException($"ManagedSoftToken: unsupported RSA sign mechanism {m}."),
    };
}
