using System.Security.Cryptography;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

// Key derivation: C_DeriveKey for ECDH1 (CKD_NULL — raw shared secret Z) and SP800-108 counter-mode
// HMAC KDF. Produces a new secret-key object whose CKA_VALUE is the derived material.
internal sealed partial class ManagedSoftToken
{
    public override CKR C_DeriveKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong baseKey,
        CK_ATTRIBUTE[]? template, NativeCULong attributeCount, ref NativeCULong key)
    {
        if (!_sessions.Contains((ulong)session)) return CKR.CKR_SESSION_HANDLE_INVALID;

        var attrs = ReadTemplate(template, attributeCount);
        int valueLen = attrs.TryGetValue((ulong)CKA.CKA_VALUE_LEN, out var vl) ? (int)ToUlong(vl) : 0;

        byte[] derived;
        switch ((CKM)(ulong)mechanism.Mechanism)
        {
            case CKM.CKM_ECDH1_DERIVE:
                if (!_asymKeys.TryGetValue((ulong)baseKey, out var alg) || alg is not ECDsa ec)
                    return CKR.CKR_KEY_HANDLE_INVALID;
                derived = DeriveEcdh(ec, ref mechanism, valueLen);
                break;

            case CKM.CKM_SP800_108_COUNTER_KDF:
                if (!_objects.TryGetValue((ulong)baseKey, out var obj) || !obj.TryGetValue((ulong)CKA.CKA_VALUE, out var keyVal))
                    return CKR.CKR_KEY_HANDLE_INVALID;
                derived = DeriveSp800108(keyVal, ref mechanism, valueLen);
                break;

            default:
                return CKR.CKR_MECHANISM_INVALID;
        }

        attrs[(ulong)CKA.CKA_VALUE] = derived;
        attrs.TryAdd((ulong)CKA.CKA_CLASS, UlongAttr((ulong)CKO.CKO_SECRET_KEY));
        key = (NativeCULong)Store(attrs);
        return CKR.CKR_OK;
    }

    // CKM_ECDH1_DERIVE with CKD_NULL: the raw shared secret Z (x-coordinate) is the keying material.
    private static byte[] DeriveEcdh(ECDsa baseEc, ref CK_MECHANISM mech, int valueLen)
    {
        var p = UnmanagedMemory.Read<CK_ECDH1_DERIVE_PARAMS>(mech.Parameter);
        byte[] peerDer = UnmanagedMemory.Read(p.PublicData, (int)p.PublicDataLen);

        ECParameters basePriv = baseEc.ExportParameters(includePrivateParameters: true);
        using var ecdh = ECDiffieHellman.Create(basePriv);
        using var peer = ECDiffieHellman.Create(new ECParameters { Curve = basePriv.Curve, Q = DecodeEcPoint(peerDer) });

        byte[] z = ecdh.DeriveRawSecretAgreement(peer.PublicKey);
        return valueLen > 0 && valueLen < z.Length ? z.AsSpan(0, valueLen).ToArray() : z;
    }

    // CKM_SP800_108_COUNTER_KDF: the adapter emits the data-param sequence
    // [0]=counter, [1]=label, [2]=0x00 separator, [3]=context, [4]=[L]. We pull label/context and run
    // the same NIST counter-mode KDF via the BCL.
    private static byte[] DeriveSp800108(byte[] baseKey, ref CK_MECHANISM mech, int valueLen)
    {
        var p = UnmanagedMemory.Read<CK_SP800_108_KDF_PARAMS>(mech.Parameter);
        int n = (int)p.NumberOfDataParams;
        int elem = UnmanagedMemory.SizeOf(typeof(CK_PRF_DATA_PARAM));
        CK_PRF_DATA_PARAM Param(int i) => UnmanagedMemory.Read<CK_PRF_DATA_PARAM>(p.DataParams + (i * elem));

        byte[] label = n > 1 ? PrfBytes(Param(1)) : [];
        byte[] context = n > 3 ? PrfBytes(Param(3)) : [];
        HashAlgorithmName prf = PrfHash((CKM)(ulong)p.PrfType);

        return SP800108HmacCounterKdf.DeriveBytes(baseKey, prf, label, context, valueLen);
    }

    private static byte[] PrfBytes(CK_PRF_DATA_PARAM prm)
        => prm.Value != IntPtr.Zero && (int)prm.ValueLen > 0 ? UnmanagedMemory.Read(prm.Value, (int)prm.ValueLen) : [];

    private static HashAlgorithmName PrfHash(CKM m) => m switch
    {
        CKM.CKM_SHA_1_HMAC => HashAlgorithmName.SHA1,
        CKM.CKM_SHA256_HMAC => HashAlgorithmName.SHA256,
        CKM.CKM_SHA384_HMAC => HashAlgorithmName.SHA384,
        CKM.CKM_SHA512_HMAC => HashAlgorithmName.SHA512,
        _ => throw new CryptographicException($"ManagedSoftToken: unsupported SP800-108 PRF {m}."),
    };

    // Inverse of EncodeEcPoint: strip the DER OCTET STRING wrapper, then split 0x04 ‖ X ‖ Y.
    private static ECPoint DecodeEcPoint(byte[] der)
    {
        int i = 1; // skip OCTET STRING tag (0x04)
        int len = der[i++];
        if (len == 0x81) len = der[i++];
        else if (len == 0x82) { len = (der[i] << 8) | der[i + 1]; i += 2; }

        byte[] point = der.AsSpan(i, len).ToArray(); // 0x04 ‖ X ‖ Y
        int fs = (point.Length - 1) / 2;
        return new ECPoint
        {
            X = point.AsSpan(1, fs).ToArray(),
            Y = point.AsSpan(1 + fs, fs).ToArray(),
        };
    }
}
