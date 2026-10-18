using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.Pkcs11Operations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal sealed partial class Pkcs11SessionCore
{
    /// <summary>
    /// Generates a secret key or set of domain parameters, creating a new object
    /// </summary>
    /// <param name="mechanism">Generation mechanism</param>
    /// <param name="attributes">Attributes of the new key or set of domain parameters</param>
    /// <returns>Handle of the new key or set of domain parameters</returns>
    public ObjectHandle GenerateKey(Mechanism mechanism, List<ObjectAttribute> attributes)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);

        Enforce(mechanism, CryptoOperation.GenerateKey);

        Log.SessionTrace(_logger, (ulong)_sessionId, "GenerateKey");

        // A secret key: refuse a deliberately weakened template, and supply the secure defaults when
        // the caller stated nothing — the same treatment DeriveKey and UnwrapKey already gave.
        using ReadOnlyDisposableList<ObjectAttribute> generatedDefaults = BuildSecureKeyDefaults(attributes, CKO.CKO_SECRET_KEY);
        if (generatedDefaults.Count > 0)
        {
            attributes = attributes is null ? [] : [.. attributes];
            attributes.AddRange(generatedDefaults);
        }

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        CK_ATTRIBUTE[]? template = BuildTemplate(attributes);

        CKR rv = _pkcs11Library.C_GenerateKey(_sessionId, in ckMechanism, template, out NativeCULong keyId);
        Pkcs11Exception.ThrowIfError(rv, OpGenerateKey);
        // Root the managed attributes past the native call: the template holds raw copies of
        // their pValue pointers, and nothing else keeps them reachable once BuildTemplate returns.
        GC.KeepAlive(attributes);

        mechanism.AbsorbOutput(mechParams);

        return new ObjectHandle((ulong)keyId);
    }

    /// <summary>
    /// Generates a public/private key pair, creating new key objects
    /// </summary>
    /// <param name="mechanism">Key generation mechanism</param>
    /// <param name="publicKeyAttributes">Attributes of the public key</param>
    /// <param name="privateKeyAttributes">Attributes of the private key</param>
    /// <param name="publicKeyHandle">Handle of the new public key</param>
    /// <param name="privateKeyHandle">Handle of the new private key</param>
    public void GenerateKeyPair(Mechanism mechanism, List<ObjectAttribute> publicKeyAttributes, List<ObjectAttribute> privateKeyAttributes, out ObjectHandle publicKeyHandle, out ObjectHandle privateKeyHandle)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);

        Enforce(mechanism, CryptoOperation.GenerateKeyPair);

        if (mechanism.Type is CKM.CKM_RSA_PKCS_KEY_PAIR_GEN or CKM.CKM_RSA_X9_31_KEY_PAIR_GEN)
        {
            // Only the first CKA_MODULUS_BITS is consulted: a template carrying two is malformed, and
            // which one the token would honour is not ours to decide.
            ObjectAttribute? modulusBits =
                publicKeyAttributes.FirstOrDefault(a => a.Type == CKA.CKA_MODULUS_BITS);
            if (modulusBits is not null)
                Enforce(new RsaKeyGenerationRequest(mechanism.Type, ModulusBitsOf(modulusBits)));
        }
        else if (mechanism.Type == CKM.CKM_EC_KEY_PAIR_GEN)
        {
            // Every EC key-pair generation meets the curve allow-list here, whichever public entry point
            // it came through. As for the modulus above, only the first CKA_EC_PARAMS is consulted; with
            // none there is no curve to judge and the token rejects the incomplete template itself.
            ObjectAttribute? ecParams =
                publicKeyAttributes.FirstOrDefault(a => a.Type == CKA.CKA_EC_PARAMS);
            if (ecParams is not null)
                Enforce(new EcKeyGenerationRequest(CurveOf(ecParams)));
        }

        Log.SessionTrace(_logger, (ulong)_sessionId, "GenerateKeyPair");

        // The private half only. CKA_SENSITIVE / CKA_EXTRACTABLE do not belong on a public key, so
        // seeding them there would be rejected by the token; the refusal alone is enough.
        using ReadOnlyDisposableList<ObjectAttribute> privateDefaults = BuildSecureKeyDefaults(privateKeyAttributes, CKO.CKO_PRIVATE_KEY);
        if (privateDefaults.Count > 0)
        {
            privateKeyAttributes = [.. privateKeyAttributes];
            privateKeyAttributes.AddRange(privateDefaults);
        }

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        CK_ATTRIBUTE[]? publicKeyTemplate = BuildTemplate(publicKeyAttributes);
        CK_ATTRIBUTE[]? privateKeyTemplate = BuildTemplate(privateKeyAttributes);

        NativeCULong publicKeyId;
        NativeCULong privateKeyId;

        // NSS bug 1012786: C_GenerateKeyPair (RSA in particular) can fail with CKR_FUNCTION_FAILED
        // under a transient RNG hiccup (e.g. an interrupted read()/getentropy() syscall). PKCS#11
        // v3.2 §11.1.1 explicitly distinguishes this from CKR_GENERAL_ERROR as retry-safe: "it is
        // possible that an attempt to make the exact same function call again would succeed."
        // Matches SunPKCS11's own workaround (p11_keymgmt.c, MAX_ATTEMPTS = 3) — no delay between
        // attempts, since the failure mode is a syscall interruption, not a slow-to-clear condition.
        const int maxAttempts = 3;
        CKR rv;
        int attempt = 0;
        do
        {
            rv = _pkcs11Library.C_GenerateKeyPair(_sessionId, in ckMechanism, publicKeyTemplate, privateKeyTemplate, out publicKeyId, out privateKeyId);
        } while (rv == CKR.CKR_FUNCTION_FAILED && ++attempt < maxAttempts);
        Pkcs11Exception.ThrowIfError(rv, OpGenerateKeyPair);
        // Root the managed attributes past the native call: the template holds raw copies of
        // their pValue pointers, and nothing else keeps them reachable once BuildTemplate returns.
        GC.KeepAlive(publicKeyAttributes);
        GC.KeepAlive(privateKeyAttributes);

        mechanism.AbsorbOutput(mechParams);

        publicKeyHandle = new ObjectHandle((ulong)publicKeyId);
        privateKeyHandle = new ObjectHandle((ulong)privateKeyId);
    }

    /// <summary>
    /// Wraps (i.e., encrypts) a private or secret key
    /// </summary>
    /// <param name="mechanism">Wrapping mechanism</param>
    /// <param name="wrappingKeyHandle">Handle of wrapping key</param>
    /// <param name="keyHandle">Handle of key to be wrapped</param>
    /// <returns>Wrapped key</returns>
    public byte[] WrapKey(Mechanism mechanism, ObjectHandle wrappingKeyHandle, ObjectHandle keyHandle)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);


        Enforce(mechanism, CryptoOperation.Wrap);

        Log.SessionTrace(_logger, (ulong)_sessionId, "WrapKey");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        byte[]? wrappedKey = mechanism.Type == CKM.CKM_AES_KEY_WRAP_KWP
            ? TryWrapKeyKwp(in ckMechanism, wrappingKeyHandle, keyHandle)
            : null;

        wrappedKey ??= CallWithLengthProbe(
            (Span<byte> buf, bool lengthOnly, out NativeCULong len) => _pkcs11Library.C_WrapKey(_sessionId, in ckMechanism, (NativeCULong)(wrappingKeyHandle.ObjectId), (NativeCULong)(keyHandle.ObjectId), buf, lengthOnly, out len),
            OpWrapKey);

        // Absorbed before returning, so the scope that owns the parameter block is still alive.
        mechanism.AbsorbOutput(mechParams);

        return wrappedKey;
    }

    // NSS bug: sftk_CryptInit's CKM_AES_KEY_WRAP_KWP case (softoken/pkcs11c.c) never sets
    // context->blockSize, unlike the sibling CKM_AES_KEY_WRAP/_PAD case (which sets it to 8).
    // NSC_Encrypt's NULL-probe formula (ulDataLen + 2*blockSize) therefore collapses to exactly
    // ulDataLen for KWP, silently omitting RFC 5649's ~8-byte overhead from the reported required
    // length -- and the follow-up too-small-buffer call doesn't correct it either, since NSS only
    // updates the output length parameter when the call succeeds. RFC 5649's wrapped length is
    // fully determined by the input length alone, so this mechanism skips the token's (for this
    // one case, untrustworthy) length probe entirely and computes the buffer size directly --
    // the same reasoning as MLKemPkcs11.EncapsulateCore handing ML-KEM a pre-sized buffer instead
    // of a NULL-buffer probe SoftHSM doesn't honour. Safe to remove once a fixed NSS is vendored.
    //
    // Only secret keys carry CKA_VALUE_LEN. A CKO_PRIVATE_KEY wraps as a PKCS#8-packaged byte
    // string whose length isn't derivable from any client-visible attribute, so this workaround
    // cannot apply there -- returns null ("not applicable") and WrapKey falls back to the normal
    // probing path. That path still hits the underlying NSS bug for a private key wrapped via
    // KWP, same as before this workaround existed, but at least fails with the token's own
    // CKR_BUFFER_TOO_SMALL rather than an unrelated "CKA_VALUE_LEN could not be read" from here.
    private byte[]? TryWrapKeyKwp(in CK_MECHANISM ckMechanism, ObjectHandle wrappingKeyHandle, ObjectHandle keyHandle)
    {
        using ReadOnlyDisposableList<ObjectAttribute> classAttrs = GetAttributeValue(keyHandle, [CKA.CKA_CLASS]);
        if (classAttrs[0].GetValueAsUlong() != (ulong)CKO.CKO_SECRET_KEY)
            return null;

        using ReadOnlyDisposableList<ObjectAttribute> attrs = GetAttributeValue(keyHandle, [CKA.CKA_VALUE_LEN]);
        ulong valueLen = attrs[0].GetValueAsUlong();
        ulong wrappedLen = 8 + ((valueLen + 7) / 8 * 8);

        byte[] buffer = new byte[wrappedLen];
        CKR rv = _pkcs11Library.C_WrapKey(_sessionId, in ckMechanism, (NativeCULong)(wrappingKeyHandle.ObjectId), (NativeCULong)(keyHandle.ObjectId), buffer, lengthOnly: false, out NativeCULong len);
        Pkcs11Exception.ThrowIfError(rv, OpWrapKey);

        return ReportedLength.Trim(buffer, len, OpWrapKey);
    }

    /// <summary>
    /// Unwraps a wrapped key using the given unwrapping key and mechanism. Throws
    /// <see cref="CryptoPolicyViolationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list and the session's policy refuses the mechanism.
    /// </summary>
    /// <param name="mechanism">Key-unwrap mechanism.</param>
    /// <param name="unwrappingKeyHandle">Handle of the unwrapping key (private RSA, AES-WRAP key, etc.).</param>
    /// <param name="wrappedKey">Wrapped key bytes to unwrap.</param>
    /// <param name="attributes">Template for the resulting unwrapped key.</param>
    /// <returns>Handle of the newly unwrapped key.</returns>
    public ObjectHandle UnwrapKey(Mechanism mechanism, ObjectHandle unwrappingKeyHandle, ReadOnlySpan<byte> wrappedKey, List<ObjectAttribute> attributes)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);


        Enforce(mechanism, CryptoOperation.Unwrap);

        Log.SessionTrace(_logger, (ulong)_sessionId, "UnwrapKey");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        // Unwrapping decrypts a key blob into a new token object. Without secure defaults a caller
        // could land an extractable, non-sensitive key — silently downgrading the posture the key
        // template builders establish. Append CKA_SENSITIVE=true / CKA_EXTRACTABLE=false when the
        // caller omitted them; an explicit insecure value requires a policy that permits it (throws otherwise).
        using ReadOnlyDisposableList<ObjectAttribute> secureDefaults = BuildSecureKeyDefaults(attributes, null);
        CK_ATTRIBUTE[]? template = BuildTemplateWithDefaults(attributes, secureDefaults);

        CKR rv = _pkcs11Library.C_UnwrapKey(_sessionId, in ckMechanism, (NativeCULong)(unwrappingKeyHandle.ObjectId), wrappedKey, template, out NativeCULong unwrappedKey);
        Pkcs11Exception.ThrowIfError(rv, OpUnwrapKey);
        // Root the managed attributes past the native call: the template holds raw copies of
        // their pValue pointers, and nothing else keeps them reachable once BuildTemplate returns.
        GC.KeepAlive(attributes);
        GC.KeepAlive(secureDefaults);

        mechanism.AbsorbOutput(mechParams);

        return new ObjectHandle((ulong)unwrappedKey);
    }

    /// <summary>
    /// Unwraps (i.e. decrypts) a wrapped key, creating a new private key or secret key object
    /// </summary>
    /// <param name="mechanism">Unwrapping mechanism</param>
    /// <param name="unwrappingKeyHandle">Handle of unwrapping key</param>
    /// <param name="wrappedKey">Wrapped key</param>
    /// <param name="attributes">Attributes for unwrapped key</param>
    /// <returns>Handle of unwrapped key</returns>
    public ObjectHandle UnwrapKey(Mechanism mechanism, ObjectHandle unwrappingKeyHandle, byte[] wrappedKey, List<ObjectAttribute> attributes)
    {
        ArgumentNullException.ThrowIfNull(wrappedKey);
        return UnwrapKey(mechanism, unwrappingKeyHandle, wrappedKey.AsSpan(), attributes);
    }

    /// <summary>
    /// The named curve a <c>CKA_EC_PARAMS</c> value selects, or the default (no-OID) curve when it names
    /// none — explicit curve parameters, a printable curve name, or an unreadable value. The default
    /// curve is on no allow-list, so a restrictive policy refuses it while AllowInsecure still permits it.
    /// </summary>
    /// <summary>
    /// Submits the type of the key an ECDH derivation or KEM will use, so a policy can refuse key
    /// agreement with a key it would never have let the caller generate (FipsOnly: X25519/X448). The
    /// mechanism alone cannot tell: <c>CKM_ECDH1_DERIVE</c> serves both Weierstrass and Montgomery keys.
    /// </summary>
    /// <remarks>
    /// A key whose <c>CKA_KEY_TYPE</c> cannot be read is left to the token. That attribute is never
    /// sensitive, so failing to read it means the handle itself is unusable and the native call that
    /// follows fails the same way.
    /// </remarks>
    private void EnforceKeyAgreementKey(Mechanism mechanism, ObjectHandle key)
    {
        if (mechanism.Type is not (CKM.CKM_ECDH1_DERIVE or CKM.CKM_ECDH1_COFACTOR_DERIVE))
            return;

        CKK keyType;
        try
        {
            using ReadOnlyDisposableList<ObjectAttribute> attrs = GetAttributeValue(key, [CKA.CKA_KEY_TYPE]);
            if (attrs[0].CannotBeRead)
                return;
            keyType = (CKK)attrs[0].GetValueAsUlong();
        }
        catch (Exception ex) when (ex is Pkcs11Exception or Pkcs11AttributeException)
        {
            return;
        }

        Enforce(new KeyAgreementKeyRequest(mechanism.Type, keyType));
    }

    // A modulus length is judged as an int. One beyond int.MaxValue is not a key any token can make; it
    // is reported as int.MaxValue, which every policy's minimum allows, so the token refuses it itself.
    private static int ModulusBitsOf(ObjectAttribute modulusBits)
    {
        ulong bits = modulusBits.GetValueAsUlong();
        return bits > int.MaxValue ? int.MaxValue : (int)bits;
    }

    private static Pkcs11ECCurve CurveOf(ObjectAttribute ecParams)
    {
        try
        {
            return Pkcs11ECCurve.FromEcParams(ecParams.GetValueAsByteArray());
        }
        catch (Exception ex) when (ex is ArgumentException or Pkcs11AttributeException)
        {
            return default;
        }
    }

    /// <summary>
    /// Submits a creation template to the policy. <paramref name="objectClass"/> is the class the
    /// creating path knows for certain; paths that take an arbitrary template pass null rather than
    /// parse the caller's CKA_CLASS.
    /// </summary>
    private void EnforceKeyTemplate(List<ObjectAttribute>? attributes, CKO? objectClass)
    {
        if (attributes is null) return;
        Enforce(new KeyTemplateRequest(objectClass, attributes));
    }

    /// <summary>
    /// Runs <see cref="EnforceKeyTemplate"/>, then returns the secure-default attributes to
    /// append for any the caller omitted — <c>CKA_SENSITIVE=true</c> and <c>CKA_EXTRACTABLE=false</c>.
    /// </summary>
    /// <remarks>
    /// Used by the paths that create a secret or private key from a template, so they all start from
    /// the same posture. The returned attributes own unmanaged buffers and must be disposed by the
    /// caller. Note the asymmetry with the refusal: <c>CKA_EXTRACTABLE=false</c> is supplied as a
    /// default here, but an explicit <c>CKA_EXTRACTABLE=true</c> is not refused — only
    /// <c>CKA_SENSITIVE=false</c> is.
    /// </remarks>
    private ReadOnlyDisposableList<ObjectAttribute> BuildSecureKeyDefaults(List<ObjectAttribute>? attributes, CKO? objectClass)
    {
        EnforceKeyTemplate(attributes, objectClass);

        bool hasSensitive = attributes?.Any(a => a.Type == CKA.CKA_SENSITIVE) ?? false;
        bool hasExtractable = attributes?.Any(a => a.Type == CKA.CKA_EXTRACTABLE) ?? false;

        List<ObjectAttribute> added = [];
        if (!hasSensitive)
            added.Add(new ObjectAttribute(CKA.CKA_SENSITIVE, true));
        if (!hasExtractable)
            added.Add(new ObjectAttribute(CKA.CKA_EXTRACTABLE, false));

        // The caller owns what comes back — these are attributes this method created, not the
        // caller's own — so hand back something that says so and can be released with a `using`.
        return new ReadOnlyDisposableList<ObjectAttribute>(added);
    }

    /// <summary>
    /// Derives a key from a base key, creating a new key object. Secure defaults
    /// (<c>CKA_SENSITIVE=true</c> / <c>CKA_EXTRACTABLE=false</c>) are applied to the result template;
    /// an explicit insecure value requires a policy that permits it (see <see cref="ICryptoPolicy"/>).
    /// </summary>
    /// <param name="mechanism">Derivation mechanism</param>
    /// <param name="baseKeyHandle">Handle of base key</param>
    /// <param name="attributes">Attributes for the new key</param>
    /// <returns>Handle of derived key</returns>
    public ObjectHandle DeriveKey(Mechanism mechanism, ObjectHandle baseKeyHandle, List<ObjectAttribute> attributes)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);


        Enforce(mechanism, CryptoOperation.Derive, attributes);
        EnforceKeyAgreementKey(mechanism, baseKeyHandle);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DeriveKey");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        // Deriving produces a new key object on the token. Apply the same secure defaults as UnwrapKey
        // (CKA_SENSITIVE=true / CKA_EXTRACTABLE=false when the caller omitted them); an explicit insecure
        // value requires a policy that permits it (throws otherwise). See BuildSecureKeyDefaults. Trusted internal
        using ReadOnlyDisposableList<ObjectAttribute> secureDefaults = BuildSecureKeyDefaults(attributes, null);
        CK_ATTRIBUTE[]? template = BuildTemplateWithDefaults(attributes, secureDefaults);

        CKR rv = _pkcs11Library.C_DeriveKey(_sessionId, in ckMechanism, (NativeCULong)(baseKeyHandle.ObjectId), template, out NativeCULong derivedKey);
        Pkcs11Exception.ThrowIfError(rv, OpDeriveKey);
        // Root the managed attributes past the native call: the template holds raw copies of
        // their pValue pointers, and nothing else keeps them reachable once BuildTemplate returns.
        GC.KeepAlive(attributes);
        GC.KeepAlive(secureDefaults);

        // SP800-108 sibling-key handles live in scope-owned slots the token wrote into; copy them
        // out before `scope` is disposed.
        mechanism.AbsorbOutput(mechParams);

        return new ObjectHandle((ulong)derivedKey);
    }
}
