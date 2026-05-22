using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// High-level helpers for PKCS#11 v3.2 functions: ML-KEM encaps/decaps, authenticated
/// wrap, signature-only verify, and validation-flags inspection.
/// </summary>
internal sealed partial class Pkcs11Session
{
    /// <summary>
    /// True when the loaded library exposes the PKCS#11 v3.2 surface (encapsulate /
    /// decapsulate / authenticated wrap / signature-only verify). On v2.40 and v3.0/v3.1
    /// libraries this is false and the corresponding methods throw
    /// <see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/>.
    /// </summary>
    public bool SupportsV32Api
        => _pkcs11Library is not null && _pkcs11Library.IsV32ApiSupported;

    // === ML-KEM: encapsulate / decapsulate =================================

    /// <summary>
    /// Encapsulates a fresh shared-secret key against <paramref name="encapsulatingPublicKey"/>
    /// (typically an ML-KEM public key). Returns the ciphertext to be sent to the holder
    /// of the matching private key, plus a handle to the freshly-derived shared-secret
    /// key on the token (PKCS#11 v3.2 §5.18.10).
    /// </summary>
    /// <param name="mechanism">Encapsulation mechanism (e.g. <see cref="CKM.CKM_ML_KEM"/>).</param>
    /// <param name="encapsulatingPublicKey">Handle of the public key to encapsulate against.</param>
    /// <param name="sharedKeyTemplate">Template applied to the derived shared-secret key.</param>
    /// <returns>Tuple of (ciphertext, sharedKeyHandle).</returns>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries.</exception>
    public (byte[] Ciphertext, ObjectHandle SharedKey) EncapsulateKey(
        Mechanism mechanism,
        ObjectHandle encapsulatingPublicKey,
        List<ObjectAttribute> sharedKeyTemplate)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(sharedKeyTemplate);

        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "EncapsulateKey");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();
        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[sharedKeyTemplate.Count];
        for (int i = 0; i < sharedKeyTemplate.Count; i++)
            template[i] = sharedKeyTemplate[i].CkAttribute;

        // Two-call: query size first, then real encaps.
        NativeCULong ctLen = (NativeCULong)0;
        NativeCULong sharedHandle = CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_EncapsulateKey(
            _sessionId, ref ckMechanism, (NativeCULong)encapsulatingPublicKey.ObjectId,
            template, (NativeCULong)template.Length,
            null!, ref ctLen, ref sharedHandle);
        // CKR_BUFFER_TOO_SMALL is a spec-valid length-probe outcome: the token populated
        // ctLen even though the (null) output buffer was inadequate (PKCS#11 v3.2 §5.2).
        // Only a genuine error aborts the probe.
        if (rv != CKR.CKR_OK && rv != CKR.CKR_BUFFER_TOO_SMALL)
            Pkcs11Exception.ThrowIfError(rv, "C_EncapsulateKey (length probe)");

        byte[] ct = new byte[(int)ctLen];
        rv = _pkcs11Library.C_EncapsulateKey(
            _sessionId, ref ckMechanism, (NativeCULong)encapsulatingPublicKey.ObjectId,
            template, (NativeCULong)template.Length,
            ct, ref ctLen, ref sharedHandle);
        Pkcs11Exception.ThrowIfError(rv, "C_EncapsulateKey");

        if (ct.Length != (int)ctLen)
            Array.Resize(ref ct, (int)ctLen);

        return (ct, new ObjectHandle((ulong)sharedHandle));
    }

    /// <summary>
    /// Decapsulates the shared-secret key from <paramref name="ciphertext"/> using
    /// <paramref name="decapsulatingPrivateKey"/> (typically an ML-KEM private key)
    /// (PKCS#11 v3.2 §5.18.11).
    /// </summary>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries.</exception>
    public ObjectHandle DecapsulateKey(
        Mechanism mechanism,
        ObjectHandle decapsulatingPrivateKey,
        ReadOnlySpan<byte> ciphertext,
        List<ObjectAttribute> sharedKeyTemplate)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(sharedKeyTemplate);

        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecapsulateKey");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();
        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[sharedKeyTemplate.Count];
        for (int i = 0; i < sharedKeyTemplate.Count; i++)
            template[i] = sharedKeyTemplate[i].CkAttribute;

        byte[] ct = ciphertext.ToArray();
        NativeCULong sharedHandle = CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_DecapsulateKey(
            _sessionId, ref ckMechanism, (NativeCULong)decapsulatingPrivateKey.ObjectId,
            template, (NativeCULong)template.Length,
            ct, (NativeCULong)ct.Length, ref sharedHandle);
        Pkcs11Exception.ThrowIfError(rv, "C_DecapsulateKey");

        return new ObjectHandle((ulong)sharedHandle);
    }

    // === Authenticated wrap ================================================

    /// <summary>
    /// Wraps <paramref name="keyToWrap"/> with <paramref name="wrappingKey"/>,
    /// binding the wrap to <paramref name="associatedData"/>. The same AAD must be
    /// supplied at unwrap or unwrap fails (PKCS#11 v3.2 §5.18.12).
    /// </summary>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries.</exception>
    public byte[] WrapKeyAuthenticated(
        Mechanism mechanism,
        ObjectHandle wrappingKey,
        ObjectHandle keyToWrap,
        ReadOnlySpan<byte> associatedData)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);
        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "WrapKeyAuthenticated");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();
        byte[] aad = associatedData.IsEmpty ? [] : associatedData.ToArray();

        NativeCULong wrappedLen = (NativeCULong)0;
        CKR rv = _pkcs11Library.C_WrapKeyAuthenticated(
            _sessionId, ref ckMechanism, (NativeCULong)wrappingKey.ObjectId, (NativeCULong)keyToWrap.ObjectId,
            aad, (NativeCULong)aad.Length, null!, ref wrappedLen);
        // CKR_BUFFER_TOO_SMALL is a spec-valid length-probe outcome (PKCS#11 v3.2 §5.2):
        // the token populated wrappedLen despite the (null) output buffer. Only a genuine
        // error aborts the probe.
        if (rv != CKR.CKR_OK && rv != CKR.CKR_BUFFER_TOO_SMALL)
            Pkcs11Exception.ThrowIfError(rv, "C_WrapKeyAuthenticated (length probe)");

        byte[] wrapped = new byte[(int)wrappedLen];
        rv = _pkcs11Library.C_WrapKeyAuthenticated(
            _sessionId, ref ckMechanism, (NativeCULong)wrappingKey.ObjectId, (NativeCULong)keyToWrap.ObjectId,
            aad, (NativeCULong)aad.Length, wrapped, ref wrappedLen);
        Pkcs11Exception.ThrowIfError(rv, "C_WrapKeyAuthenticated");

        if (wrapped.Length != (int)wrappedLen)
            Array.Resize(ref wrapped, (int)wrappedLen);

        return wrapped;
    }

    /// <summary>
    /// Unwraps <paramref name="wrappedKey"/> using <paramref name="unwrappingKey"/>,
    /// verifying that the wrap was authenticated against <paramref name="associatedData"/>.
    /// </summary>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2; <see cref="CKR.CKR_AEAD_DECRYPT_FAILED"/> when the AAD doesn't match.</exception>
    public ObjectHandle UnwrapKeyAuthenticated(
        Mechanism mechanism,
        ObjectHandle unwrappingKey,
        ReadOnlySpan<byte> wrappedKey,
        ReadOnlySpan<byte> associatedData,
        List<ObjectAttribute> unwrappedKeyTemplate)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(unwrappedKeyTemplate);
        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "UnwrapKeyAuthenticated");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();
        byte[] wrapped = wrappedKey.ToArray();
        byte[] aad = associatedData.IsEmpty ? [] : associatedData.ToArray();

        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[unwrappedKeyTemplate.Count];
        for (int i = 0; i < unwrappedKeyTemplate.Count; i++)
            template[i] = unwrappedKeyTemplate[i].CkAttribute;

        NativeCULong newKey = CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_UnwrapKeyAuthenticated(
            _sessionId, ref ckMechanism, (NativeCULong)unwrappingKey.ObjectId,
            wrapped, (NativeCULong)wrapped.Length,
            template, (NativeCULong)template.Length,
            aad, (NativeCULong)aad.Length, ref newKey);
        Pkcs11Exception.ThrowIfError(rv, "C_UnwrapKeyAuthenticated");

        return new ObjectHandle((ulong)newKey);
    }

    // === Signature-only verify (init binds the signature, data feeds in) ====

    /// <summary>
    /// One-shot streaming-friendly signature-only verify (PKCS#11 v3.2 §5.16.10–11).
    /// Unlike <c>Verify</c>, the signature is bound at init time so the data can be
    /// fed as a stream. This is a one-shot wrapper that supplies all data at once.
    /// </summary>
    /// <returns><c>true</c> if the signature verifies; <c>false</c> on <see cref="CKR.CKR_SIGNATURE_INVALID"/>.</returns>
    /// <exception cref="Pkcs11Exception">Any other PKCS#11 error.</exception>
    public bool VerifySignature(
        Mechanism mechanism,
        ObjectHandle verificationKey,
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);
        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "VerifySignature");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();
        byte[] sig = signature.ToArray();
        byte[] dataBuf = data.ToArray();

        CKR rv = _pkcs11Library.C_VerifySignatureInit(
            _sessionId, ref ckMechanism, (NativeCULong)verificationKey.ObjectId,
            sig, (NativeCULong)sig.Length);
        Pkcs11Exception.ThrowIfError(rv, "C_VerifySignatureInit");

        rv = _pkcs11Library.C_VerifySignature(_sessionId, dataBuf, (NativeCULong)dataBuf.Length);
        if (rv == CKR.CKR_OK) return true;
        if (rv == CKR.CKR_SIGNATURE_INVALID) return false;
        throw Pkcs11Exception.Create(rv, "C_VerifySignature");
    }

    /// <summary>
    /// Streaming signature-only verify: binds <paramref name="signature"/> at init,
    /// then feeds <paramref name="inputStream"/> through C_VerifySignatureUpdate and
    /// finalizes via C_VerifySignatureFinal.
    /// </summary>
    /// <returns><c>true</c> if the signature verifies; <c>false</c> on <see cref="CKR.CKR_SIGNATURE_INVALID"/>.</returns>
    public bool VerifySignature(
        Mechanism mechanism,
        ObjectHandle verificationKey,
        ReadOnlySpan<byte> signature,
        Stream inputStream,
        int bufferLength = 4096)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(inputStream);
        if (bufferLength < 1)
            throw new ArgumentException("Value has to be a positive number.", nameof(bufferLength));
        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "VerifySignature(stream)");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();
        byte[] sig = signature.ToArray();

        CKR rv = _pkcs11Library.C_VerifySignatureInit(
            _sessionId, ref ckMechanism, (NativeCULong)verificationKey.ObjectId,
            sig, (NativeCULong)sig.Length);
        Pkcs11Exception.ThrowIfError(rv, "C_VerifySignatureInit");

        byte[] buffer = new byte[bufferLength];
        int read;
        while ((read = inputStream.Read(buffer, 0, buffer.Length)) > 0)
        {
            rv = _pkcs11Library.C_VerifySignatureUpdate(_sessionId, buffer, (NativeCULong)read);
            Pkcs11Exception.ThrowIfError(rv, "C_VerifySignatureUpdate");
        }

        rv = _pkcs11Library.C_VerifySignatureFinal(_sessionId);
        if (rv == CKR.CKR_OK) return true;
        if (rv == CKR.CKR_SIGNATURE_INVALID) return false;
        throw Pkcs11Exception.Create(rv, "C_VerifySignatureFinal");
    }

    // === Validation flags ==================================================

    /// <summary>
    /// Reads the session's validation flags for the requested validation-state type
    /// (PKCS#11 v3.2 §5.6.10). <paramref name="validationType"/> is typically
    /// <c>CKS_LAST_VALIDATION_OK</c> to query whether the most recent
    /// operation completed within the active validation profile.
    /// </summary>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries.</exception>
    public ulong GetSessionValidationFlags(ulong validationType)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.SessionGetValidationFlags(_logger, (ulong)_sessionId, validationType);

        NativeCULong flags = (NativeCULong)0;
        CKR rv = _pkcs11Library.C_GetSessionValidationFlags(_sessionId, (NativeCULong)validationType, ref flags);
        Pkcs11Exception.ThrowIfError(rv, "C_GetSessionValidationFlags");

        return (ulong)flags;
    }
}
