using KerckhoffsLabs.Security.Cryptography.Pkcs11;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal sealed partial class Pkcs11Session
{
    /// <summary>
    /// Signs <paramref name="data"/> using the given mechanism and key. Throws
    /// <see cref="InsecureOperationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list and <see cref="AllowInsecure"/> is false.
    /// </summary>
    /// <param name="mechanism">Signing mechanism.</param>
    /// <param name="keyHandle">Handle of the private/MAC key.</param>
    /// <param name="data">Data to sign.</param>
    /// <returns>Signature bytes (size depends on key + mechanism).</returns>
    public byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);
        GuardMechanism((CKM)mechanism.Type);

        _logger.LogDebug("Session({SessionId})::Sign", _sessionId);

        // Temporary array for the byte[]-based P/Invoke path. Replace with pinned-Span
        // P/Invoke when perf profiling proves it matters.
        byte[] buffer = data.ToArray();
        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_SignInit(_sessionId, ref ckMechanism, (NativeCULong)keyHandle.ObjectId);
        Pkcs11Exception.ThrowIfError(rv, "C_SignInit");

        NativeCULong signatureLen = (NativeCULong)0;
        rv = _pkcs11Library.C_Sign(_sessionId, buffer, (NativeCULong)buffer.Length, null, ref signatureLen);
        Pkcs11Exception.ThrowIfError(rv, "C_Sign");

        byte[] signature = new byte[(int)signatureLen];
        rv = _pkcs11Library.C_Sign(_sessionId, buffer, (NativeCULong)buffer.Length, signature, ref signatureLen);
        Pkcs11Exception.ThrowIfError(rv, "C_Sign");

        if (signature.Length != (int)signatureLen)
            Array.Resize(ref signature, (int)signatureLen);

        return signature;
    }

    // === Secure-default signing helpers ====================================

    /// <summary>
    /// Signs <paramref name="data"/> using RSA-PSS with SHA-256, MGF1+SHA-256, and a 32-byte salt
    /// (matching the hash output length per RFC 8017).
    /// </summary>
    /// <param name="privateKeyHandle">Handle of an RSA private key (CKA_SIGN=true).</param>
    /// <param name="data">Data to sign.</param>
    /// <returns>Signature bytes (length = RSA modulus / 8).</returns>
    public byte[] SignRsaPss(ObjectHandle privateKeyHandle, ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        using var p = new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, saltLength: 32);
        using var mechanism = new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, p);
        return Sign(mechanism, privateKeyHandle, data);
    }

    /// <summary>
    /// Signs <paramref name="data"/> using ECDSA with SHA-256 — the standard modern ECDSA mode.
    /// Output is the raw concatenated (r || s) form per PKCS#11 §2.3.6.
    /// </summary>
    /// <param name="privateKeyHandle">Handle of an EC private key on a strong curve (P-256+, secp256k1, P-384, P-521).</param>
    /// <param name="data">Data to sign.</param>
    /// <returns>Signature bytes (2 × curve coordinate length; 64 bytes for P-256).</returns>
    public byte[] SignEcdsa(ObjectHandle privateKeyHandle, ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        if (SupportsMechanism(CKM.CKM_ECDSA_SHA256))
        {
            using var mechanism = new Mechanism(CKM.CKM_ECDSA_SHA256);
            return Sign(mechanism, privateKeyHandle, data);
        }
        // Fallback: pre-hash in managed code and use raw CKM_ECDSA.
        byte[] hash = System.Security.Cryptography.SHA256.HashData(data);
        using var rawMechanism = new Mechanism(CKM.CKM_ECDSA);
        return Sign(rawMechanism, privateKeyHandle, hash);
    }

    /// <summary>
    /// Signs <paramref name="data"/> using Ed25519 (EdDSA over Curve25519).
    /// Output is a fixed 64-byte signature.
    /// </summary>
    /// <param name="privateKeyHandle">Handle of an Ed25519 private key (CKK_EC_EDWARDS, CKA_EC_PARAMS=Ed25519 OID).</param>
    /// <param name="data">Data to sign.</param>
    /// <returns>64-byte Ed25519 signature.</returns>
    public byte[] SignEd25519(ObjectHandle privateKeyHandle, ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        using var mechanism = new Mechanism(CKM.CKM_EDDSA);
        return Sign(mechanism, privateKeyHandle, data);
    }

    /// <summary>
    /// Signs <paramref name="data"/> using Ed448 (EdDSA over Curve448).
    /// Output is a fixed 114-byte signature.
    /// </summary>
    /// <param name="privateKeyHandle">Handle of an Ed448 private key (CKK_EC_EDWARDS, CKA_EC_PARAMS=Ed448 OID).</param>
    /// <param name="data">Data to sign.</param>
    /// <returns>114-byte Ed448 signature.</returns>
    public byte[] SignEd448(ObjectHandle privateKeyHandle, ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        using var mechanism = new Mechanism(CKM.CKM_EDDSA);
        return Sign(mechanism, privateKeyHandle, data);
    }

    // === Legacy named shortcut (gated, compile-time warning) ===============

    /// <summary>
    /// Signs using RSA PKCS#1 v1.5 padding. **Use <see cref="SignRsaPss"/> instead.**
    /// This method exists for compatibility; it throws <see cref="InsecureOperationException"/>
    /// at runtime unless <see cref="AllowInsecure"/> is set on the session.
    /// </summary>
    [Obsolete("RSA PKCS#1 v1.5 signing is vulnerable to fault attacks and is not recommended for new code. " +
              "Use SignRsaPss instead. If you must use it, set Session.AllowInsecure = true.")]
    public byte[] SignRsaPkcs1V15(ObjectHandle privateKeyHandle, ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        using var mechanism = new Mechanism(CKM.CKM_RSA_PKCS);
        return Sign(mechanism, privateKeyHandle, data);
    }
}
