using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.Pkcs11Operations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal sealed partial class Pkcs11SessionCore
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
    /// <param name="expectedCiphertextLen">
    /// When &gt; 0, the exact ciphertext length is already known (e.g. fixed by the ML-KEM parameter
    /// set), so a single <c>C_EncapsulateKey</c> call is made with a pre-sized buffer. This skips the
    /// NULL-buffer length probe, which some tokens (SoftHSM) do not honour for <c>C_EncapsulateKey</c>:
    /// they leave <c>*pulCipherTextLen</c> untouched on a NULL buffer yet still run a full,
    /// side-effectful encapsulation per call, so a probe would both fail to report the size and leak an
    /// extra shared-secret object. When 0, the two-call probe is used (caller does not know the size).
    /// </param>
    /// <returns>Tuple of (ciphertext, sharedKeyHandle).</returns>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries.</exception>
    public (byte[] Ciphertext, ObjectHandle SharedKey) EncapsulateKey(
        Mechanism mechanism,
        ObjectHandle encapsulatingPublicKey,
        List<ObjectAttribute> sharedKeyTemplate,
        int expectedCiphertextLen = 0)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(sharedKeyTemplate);

        Enforce(mechanism, CryptoOperation.Encapsulate);
        EnforceKeyAgreementKey(mechanism, encapsulatingPublicKey);

        Log.SessionTrace(_logger, (ulong)_sessionId, "EncapsulateKey");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        // The encapsulated shared secret is a new key object on the token. Apply the same secure
        // defaults as UnwrapKey (CKA_SENSITIVE=true / CKA_EXTRACTABLE=false when omitted); an explicit
        // insecure value requires a policy that permits it. See BuildSecureKeyDefaults.
        using ReadOnlyDisposableList<ObjectAttribute> secureDefaults = BuildSecureKeyDefaults(sharedKeyTemplate, null);
        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[sharedKeyTemplate.Count + secureDefaults.Count];
        int idx = 0;
        for (int i = 0; i < sharedKeyTemplate.Count; i++)
            template[idx++] = sharedKeyTemplate[i].CkAttribute;
        foreach (ObjectAttribute d in secureDefaults)
            template[idx++] = d.CkAttribute;

        NativeCULong ctLen;
        NativeCULong sharedHandle = (NativeCULong)CK.CK_INVALID_HANDLE;
        CKR rv;
        byte[] ct;

        if (expectedCiphertextLen > 0)
        {
            // Single-call: the exact ciphertext size is known, so hand the token a correctly-sized
            // buffer and let it fill it in one shot. This is the spec-correct path on every token
            // and the only correct path on SoftHSM, whose C_EncapsulateKey ignores a NULL buffer
            // (no length probe) and performs a side-effectful encapsulation on each call.
            ct = new byte[expectedCiphertextLen];
            rv = _pkcs11Library.C_EncapsulateKey(
                _sessionId, in ckMechanism, (NativeCULong)encapsulatingPublicKey.ObjectId,
                template,
                ct, lengthOnly: false, out ctLen, out sharedHandle);
            Pkcs11Exception.ThrowIfError(rv, OpEncapsulateKey);
        }
        else
        {
            // Two-call: query size first, then real encaps (size unknown to the caller).
            rv = _pkcs11Library.C_EncapsulateKey(
                _sessionId, in ckMechanism, (NativeCULong)encapsulatingPublicKey.ObjectId,
                template,
                default, lengthOnly: true, out ctLen, out sharedHandle);
            // CKR_BUFFER_TOO_SMALL is a spec-valid length-probe outcome: the token populated
            // ctLen even though the (null) output buffer was inadequate (PKCS#11 v3.2 §5.2).
            // Only a genuine error aborts the probe.
            if (rv is not CKR.CKR_OK and not CKR.CKR_BUFFER_TOO_SMALL)
                Pkcs11Exception.ThrowIfError(rv, "C_EncapsulateKey (length probe)");

            // A token that ignores the probe (SoftHSM does) reports no size at all. Continuing would
            // allocate an empty buffer and hand the caller an empty ciphertext for an encapsulation
            // the token really performed, side effects and all — so fail here instead. The CKR is
            // synthesized: no native call failed, but the caller is who must act, and
            // CKR_BUFFER_TOO_SMALL maps to Pkcs11ArgumentException, which says so. Callers that know
            // the size pass expectedCiphertextLen and never reach this path.
            if (ctLen == (NativeCULong)0)
                throw Pkcs11Exception.Create(CKR.CKR_BUFFER_TOO_SMALL,
                    "C_EncapsulateKey (length probe reported no size — pass expectedCiphertextLen)");

            ct = new byte[ReportedLength.ForAllocation(ctLen, OpEncapsulateKey)];
            rv = _pkcs11Library.C_EncapsulateKey(
                _sessionId, in ckMechanism, (NativeCULong)encapsulatingPublicKey.ObjectId,
                template,
                ct, lengthOnly: false, out ctLen, out sharedHandle);
            Pkcs11Exception.ThrowIfError(rv, OpEncapsulateKey);
        }

        mechanism.AbsorbOutput(mechParams);

        ct = ReportedLength.Trim(ct, ctLen, OpEncapsulateKey);

        // Root the managed attributes past every C_EncapsulateKey call above (probe and real):
        // the template holds raw copies of their pValue pointers.
        GC.KeepAlive(sharedKeyTemplate);
        GC.KeepAlive(secureDefaults);
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

        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(sharedKeyTemplate);

        Enforce(mechanism, CryptoOperation.Decapsulate);
        EnforceKeyAgreementKey(mechanism, decapsulatingPrivateKey);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecapsulateKey");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        // The decapsulated shared secret is a new key object on the token. Apply the same secure
        // defaults as UnwrapKey (CKA_SENSITIVE=true / CKA_EXTRACTABLE=false when omitted); an explicit
        // insecure value requires a policy that permits it. See BuildSecureKeyDefaults.
        using ReadOnlyDisposableList<ObjectAttribute> secureDefaults = BuildSecureKeyDefaults(sharedKeyTemplate, null);
        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[sharedKeyTemplate.Count + secureDefaults.Count];
        int idx = 0;
        for (int i = 0; i < sharedKeyTemplate.Count; i++)
            template[idx++] = sharedKeyTemplate[i].CkAttribute;
        foreach (ObjectAttribute d in secureDefaults)
            template[idx++] = d.CkAttribute;

        NativeCULong sharedHandle = (NativeCULong)CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_DecapsulateKey(
            _sessionId, in ckMechanism, (NativeCULong)decapsulatingPrivateKey.ObjectId,
            template,
            ciphertext, out sharedHandle);
        Pkcs11Exception.ThrowIfError(rv, OpDecapsulateKey);
        // Root the managed attributes past the native call: the template holds raw copies of
        // their pValue pointers, and nothing else keeps them reachable once the loop above returns.
        GC.KeepAlive(sharedKeyTemplate);
        GC.KeepAlive(secureDefaults);

        mechanism.AbsorbOutput(mechParams);

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

        ArgumentNullException.ThrowIfNull(mechanism);
        Enforce(mechanism, CryptoOperation.Wrap);

        Log.SessionTrace(_logger, (ulong)_sessionId, "WrapKeyAuthenticated");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        CKR rv = _pkcs11Library.C_WrapKeyAuthenticated(
            _sessionId, in ckMechanism, (NativeCULong)wrappingKey.ObjectId, (NativeCULong)keyToWrap.ObjectId,
            associatedData, default, lengthOnly: true, out NativeCULong wrappedLen);
        // CKR_BUFFER_TOO_SMALL is a spec-valid length-probe outcome (PKCS#11 v3.2 §5.2):
        // the token populated wrappedLen despite the (null) output buffer. Only a genuine
        // error aborts the probe.
        if (rv is not CKR.CKR_OK and not CKR.CKR_BUFFER_TOO_SMALL)
            Pkcs11Exception.ThrowIfError(rv, "C_WrapKeyAuthenticated (length probe)");

        byte[] wrapped = new byte[ReportedLength.ForAllocation(wrappedLen, OpWrapKeyAuthenticated)];
        rv = _pkcs11Library.C_WrapKeyAuthenticated(
            _sessionId, in ckMechanism, (NativeCULong)wrappingKey.ObjectId, (NativeCULong)keyToWrap.ObjectId,
            associatedData, wrapped, lengthOnly: false, out wrappedLen);
        Pkcs11Exception.ThrowIfError(rv, OpWrapKeyAuthenticated);

        mechanism.AbsorbOutput(mechParams);

        return ReportedLength.Trim(wrapped, wrappedLen, OpWrapKeyAuthenticated);
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

        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(unwrappedKeyTemplate);
        Enforce(mechanism, CryptoOperation.Unwrap);

        Log.SessionTrace(_logger, (ulong)_sessionId, "UnwrapKeyAuthenticated");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        // Authenticated unwrap lands a new key object on the token, exactly as UnwrapKey does. Apply the
        // same secure defaults (CKA_SENSITIVE=true / CKA_EXTRACTABLE=false when omitted); an explicit
        // insecure value requires a policy that permits it. See BuildSecureKeyDefaults.
        using ReadOnlyDisposableList<ObjectAttribute> secureDefaults = BuildSecureKeyDefaults(unwrappedKeyTemplate, null);
        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[unwrappedKeyTemplate.Count + secureDefaults.Count];
        int idx = 0;
        for (int i = 0; i < unwrappedKeyTemplate.Count; i++)
            template[idx++] = unwrappedKeyTemplate[i].CkAttribute;
        foreach (ObjectAttribute d in secureDefaults)
            template[idx++] = d.CkAttribute;

        NativeCULong newKey = (NativeCULong)CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_UnwrapKeyAuthenticated(
            _sessionId, in ckMechanism, (NativeCULong)unwrappingKey.ObjectId,
            wrappedKey,
            template,
            associatedData, out newKey);
        Pkcs11Exception.ThrowIfError(rv, OpUnwrapKeyAuthenticated);
        // Root the managed attributes past the native call: the template holds raw copies of
        // their pValue pointers, and nothing else keeps them reachable once the loop above returns.
        GC.KeepAlive(unwrappedKeyTemplate);
        GC.KeepAlive(secureDefaults);

        mechanism.AbsorbOutput(mechParams);

        return new ObjectHandle((ulong)newKey);
    }

    // === Signature-only verify (init binds the signature, data feeds in) ====

    /// <summary>
    /// One-shot streaming-friendly signature-only verify (PKCS#11 v3.2 §5.16.10–11).
    /// Unlike <c>Verify</c>, the signature is bound at init time so the data can be
    /// fed as a stream. This is a one-shot wrapper that supplies all data at once.
    /// </summary>
    /// <returns><see langword="true"/> if the signature verifies; <see langword="false"/> on <see cref="CKR.CKR_SIGNATURE_INVALID"/>.</returns>
    /// <exception cref="Pkcs11Exception">Any other PKCS#11 error.</exception>
    public bool VerifySignature(
        Mechanism mechanism,
        ObjectHandle verificationKey,
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);
        Enforce(mechanism, CryptoOperation.Verify);

        Log.SessionTrace(_logger, (ulong)_sessionId, "VerifySignature");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("VerifySignature");
        CKR rv = _pkcs11Library.C_VerifySignatureInit(
            _sessionId, in ckMechanism, (NativeCULong)verificationKey.ObjectId,
            signature);
        operation.Begin(CKF.CKF_VERIFY, rv, OpVerifySignatureInit);

        rv = _pkcs11Library.C_VerifySignature(_sessionId, data);
        operation.Completed(); // C_VerifySignature ends the operation whatever it returns
        bool verified = IsVerified(rv, OpVerifySignature);

        // Absorbed before returning, so the scope that owns the parameter block is still alive.
        mechanism.AbsorbOutput(mechParams);

        return verified;
    }

    /// <summary>
    /// Streaming signature-only verify: binds <paramref name="signature"/> at init,
    /// then feeds <paramref name="inputStream"/> through C_VerifySignatureUpdate and
    /// finalizes via C_VerifySignatureFinal.
    /// </summary>
    /// <returns><see langword="true"/> if the signature verifies; <see langword="false"/> on <see cref="CKR.CKR_SIGNATURE_INVALID"/>.</returns>
    public bool VerifySignature(
        Mechanism mechanism,
        ObjectHandle verificationKey,
        ReadOnlySpan<byte> signature,
        Stream inputStream,
        int bufferLength = 4096)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(inputStream);
        if (bufferLength < 1)
            throw new ArgumentException("Value has to be a positive number.", nameof(bufferLength));
        Enforce(mechanism, CryptoOperation.Verify);

        Log.SessionTrace(_logger, (ulong)_sessionId, "VerifySignature(stream)");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("VerifySignature");
        CKR rv = _pkcs11Library.C_VerifySignatureInit(
            _sessionId, in ckMechanism, (NativeCULong)verificationKey.ObjectId,
            signature);
        operation.Begin(CKF.CKF_VERIFY, rv, OpVerifySignatureInit);

        byte[] buffer = new byte[bufferLength];
        int read;
        while ((read = inputStream.Read(buffer, 0, buffer.Length)) > 0)
        {
            rv = _pkcs11Library.C_VerifySignatureUpdate(_sessionId, buffer.AsSpan(0, read));
            Pkcs11Exception.ThrowIfError(rv, OpVerifySignatureUpdate);
        }

        rv = _pkcs11Library.C_VerifySignatureFinal(_sessionId);
        // C_VerifySignatureFinal always finalizes — whether the signature was valid, invalid, or
        // the call failed with any other CKR — the verify operation is consumed.
        operation.Completed();
        bool verified = IsVerified(rv, OpVerifySignatureFinal);

        // Absorbed before returning, so the scope that owns the parameter block is still alive.
        mechanism.AbsorbOutput(mechParams);

        return verified;
    }

    // === Validation flags ==================================================

    /// <summary>
    /// Reads the session's validation flags for the requested validation-state type
    /// (PKCS#11 v3.2 §5.6.10). <paramref name="validationType"/> is typically
    /// <see cref="CksValidationFlagsType.CKS_LAST_VALIDATION_OK"/> to query whether the most recent
    /// operation completed within the active validation profile.
    /// </summary>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on pre-v3.2 libraries.</exception>
    public ulong GetSessionValidationFlags(CksValidationFlagsType validationType)
    {
        using var _ = AcquireExclusive();

        Log.SessionGetValidationFlags(_logger, (ulong)_sessionId, (ulong)validationType);

        CKR rv = _pkcs11Library.C_GetSessionValidationFlags(_sessionId, (NativeCULong)(ulong)validationType, out NativeCULong flags);
        Pkcs11Exception.ThrowIfError(rv, OpGetSessionValidationFlags);

        return (ulong)flags;
    }
}
