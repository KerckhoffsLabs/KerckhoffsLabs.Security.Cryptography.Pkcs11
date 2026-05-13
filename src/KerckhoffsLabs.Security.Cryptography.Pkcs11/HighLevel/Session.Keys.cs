using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public partial class Session
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
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        GuardMechanism((CKM)mechanism.Type);

        _logger.LogDebug("Session({SessionId})::GenerateKey", _sessionId);

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CK_ATTRIBUTE[] template = null;
        NativeCULong templateLength = (NativeCULong)0;

        if (attributes != null)
        {
            templateLength = (NativeCULong)(attributes.Count);
            template = new CK_ATTRIBUTE[(int)templateLength];
            for (int i = 0; i < (int)(templateLength); i++)
                template[i] = attributes[i].CkAttribute;
        }

        NativeCULong keyId = CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_GenerateKey(_sessionId, ref ckMechanism, template, templateLength, ref keyId);
        Pkcs11Exception.ThrowIfError(rv, "C_GenerateKey");

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
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        GuardMechanism((CKM)mechanism.Type);

        _logger.LogDebug("Session({SessionId})::GenerateKeyPair", _sessionId);

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CK_ATTRIBUTE[] publicKeyTemplate = null;
        NativeCULong publicKeyTemplateLength = (NativeCULong)0;

        if (publicKeyAttributes != null)
        {
            publicKeyTemplateLength = (NativeCULong)(publicKeyAttributes.Count);
            publicKeyTemplate = new CK_ATTRIBUTE[(int)publicKeyTemplateLength];
            for (int i = 0; i < (int)(publicKeyTemplateLength); i++)
                publicKeyTemplate[i] = publicKeyAttributes[i].CkAttribute;
        }

        CK_ATTRIBUTE[] privateKeyTemplate = null;
        NativeCULong privateKeyTemplateLength = (NativeCULong)0;

        if (privateKeyAttributes != null)
        {
            privateKeyTemplateLength = (NativeCULong)(privateKeyAttributes.Count);
            privateKeyTemplate = new CK_ATTRIBUTE[(int)privateKeyTemplateLength];
            for (int i = 0; i < (int)(privateKeyTemplateLength); i++)
                privateKeyTemplate[i] = privateKeyAttributes[i].CkAttribute;
        }

        NativeCULong publicKeyId = CK.CK_INVALID_HANDLE;
        NativeCULong privateKeyId = CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_GenerateKeyPair(_sessionId, ref ckMechanism, publicKeyTemplate, publicKeyTemplateLength, privateKeyTemplate, privateKeyTemplateLength, ref publicKeyId, ref privateKeyId);
        Pkcs11Exception.ThrowIfError(rv, "C_GenerateKeyPair");

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
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (wrappingKeyHandle == null)
            throw new ArgumentNullException("wrappingKeyHandle");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.LogDebug("Session({SessionId})::WrapKey", _sessionId);

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        NativeCULong wrappedKeyLen = (NativeCULong)0;
        CKR rv = _pkcs11Library.C_WrapKey(_sessionId, ref ckMechanism, (NativeCULong)(wrappingKeyHandle.ObjectId), (NativeCULong)(keyHandle.ObjectId), null, ref wrappedKeyLen);
        Pkcs11Exception.ThrowIfError(rv, "C_WrapKey");

        byte[] wrappedKey = new byte[(int)wrappedKeyLen];
        rv = _pkcs11Library.C_WrapKey(_sessionId, ref ckMechanism, (NativeCULong)(wrappingKeyHandle.ObjectId), (NativeCULong)(keyHandle.ObjectId), wrappedKey, ref wrappedKeyLen);
        Pkcs11Exception.ThrowIfError(rv, "C_WrapKey");

        if (wrappedKey.Length != (int)(wrappedKeyLen))
            Array.Resize(ref wrappedKey, (int)(wrappedKeyLen));

        return wrappedKey;
    }

    /// <summary>
    /// Unwraps a wrapped key using the given unwrapping key and mechanism. Throws
    /// <see cref="InsecureOperationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list and <see cref="AllowInsecure"/> is false.
    /// </summary>
    /// <param name="mechanism">Key-unwrap mechanism.</param>
    /// <param name="unwrappingKeyHandle">Handle of the unwrapping key (private RSA, AES-WRAP key, etc.).</param>
    /// <param name="wrappedKey">Wrapped key bytes to unwrap.</param>
    /// <param name="attributes">Template for the resulting unwrapped key.</param>
    /// <returns>Handle of the newly unwrapped key.</returns>
    public ObjectHandle UnwrapKey(Mechanism mechanism, ObjectHandle unwrappingKeyHandle, ReadOnlySpan<byte> wrappedKey, List<ObjectAttribute> attributes)
    {
        using var _ = AcquireExclusive();
        if (_disposed) throw new ObjectDisposedException(GetType().FullName);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(unwrappingKeyHandle);
        ArgumentNullException.ThrowIfNull(attributes);
        // Temporary array for the byte[]-based P/Invoke path. Replace with pinned-Span
        // P/Invoke when perf profiling proves it matters.
        byte[] buffer = wrappedKey.ToArray();
        return UnwrapKey(mechanism, unwrappingKeyHandle, buffer, attributes);
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
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (unwrappingKeyHandle == null)
            throw new ArgumentNullException("unwrappingKeyHandle");

        if (wrappedKey == null)
            throw new ArgumentNullException("wrappedKey");

        GuardMechanism((CKM)mechanism.Type);

        _logger.LogDebug("Session({SessionId})::UnwrapKey", _sessionId);

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CK_ATTRIBUTE[] template = null;
        NativeCULong templateLen = (NativeCULong)0;
        if (attributes != null)
        {
            template = new CK_ATTRIBUTE[attributes.Count];
            for (int i = 0; i < attributes.Count; i++)
                template[i] = attributes[i].CkAttribute;
            templateLen = (NativeCULong)(attributes.Count);
        }

        NativeCULong unwrappedKey = CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_UnwrapKey(_sessionId, ref ckMechanism, (NativeCULong)(unwrappingKeyHandle.ObjectId), wrappedKey, (NativeCULong)(wrappedKey.Length), template, templateLen, ref unwrappedKey);
        Pkcs11Exception.ThrowIfError(rv, "C_UnwrapKey");

        return new ObjectHandle((ulong)unwrappedKey);
    }

    // === Secure-default key-generation helpers =============================

    /// <summary>
    /// Generates an AES key of the specified bit length as a session-only, non-extractable,
    /// sensitive secret key. Defaults to 256-bit AES.
    /// </summary>
    /// <param name="bitLength">Key length in bits — 128, 192, or 256. Default 256.</param>
    /// <param name="label">Optional CKA_LABEL value. Defaults to none.</param>
    /// <param name="persistOnToken">If true, the key is created with CKA_TOKEN=true (persistent). Default false (session-only).</param>
    /// <returns>Handle of the new AES key.</returns>
    public ObjectHandle GenerateAesKey(int bitLength = 256, string? label = null, bool persistOnToken = false)
    {
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (bitLength != 128 && bitLength != 192 && bitLength != 256)
            throw new ArgumentOutOfRangeException(nameof(bitLength), "AES key length must be 128, 192, or 256 bits.");

        using var mechanism = new Mechanism(CKM.CKM_AES_KEY_GEN);

        using var attrClass      = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrKeyType    = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
        using var attrValueLen   = new ObjectAttribute(CKA.CKA_VALUE_LEN, (ulong)(bitLength / 8));
        using var attrToken      = new ObjectAttribute(CKA.CKA_TOKEN, persistOnToken);
        using var attrSensitive  = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var attrExtract    = new ObjectAttribute(CKA.CKA_EXTRACTABLE, false);
        using var attrEncrypt    = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
        using var attrDecrypt    = new ObjectAttribute(CKA.CKA_DECRYPT, true);
        using var attrWrap       = new ObjectAttribute(CKA.CKA_WRAP, true);
        using var attrUnwrap     = new ObjectAttribute(CKA.CKA_UNWRAP, true);
        using var attrModifiable = new ObjectAttribute(CKA.CKA_MODIFIABLE, false);

        var template = new List<ObjectAttribute> { attrClass, attrKeyType, attrValueLen, attrToken, attrSensitive, attrExtract, attrEncrypt, attrDecrypt, attrWrap, attrUnwrap, attrModifiable };
        if (label is not null)
        {
            using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            template.Add(attrLabel);
            return GenerateKey(mechanism, template);
        }

        return GenerateKey(mechanism, template);
    }

    /// <summary>
    /// Generates an RSA key pair as session objects (private key non-extractable + sensitive,
    /// CKA_TOKEN=false). Defaults to RSA-2048 with the standard exponent 65537.
    /// </summary>
    /// <param name="modulusBits">Modulus length in bits — must be ≥ 2048 (PKCS#11 recommends ≥ 2048 since the 2014 update). Default 2048.</param>
    /// <param name="label">Optional CKA_LABEL value applied to BOTH public and private key. Defaults to none.</param>
    /// <param name="persistOnToken">If true, both keys created with CKA_TOKEN=true. Default false.</param>
    /// <returns>(publicKeyHandle, privateKeyHandle) tuple.</returns>
    public (ObjectHandle pub, ObjectHandle priv) GenerateRsaKeyPair(int modulusBits = 2048, string? label = null, bool persistOnToken = false)
    {
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (modulusBits < 2048)
            throw new ArgumentOutOfRangeException(nameof(modulusBits), "RSA modulus must be ≥ 2048 bits (NIST SP 800-131A).");

        using var mechanism = new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);

        using var pubClass       = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var pubKeyType     = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA);
        using var pubToken       = new ObjectAttribute(CKA.CKA_TOKEN, persistOnToken);
        using var pubEncrypt     = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
        using var pubVerify      = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var pubWrap        = new ObjectAttribute(CKA.CKA_WRAP, true);
        using var pubModBits     = new ObjectAttribute(CKA.CKA_MODULUS_BITS, (ulong)modulusBits);
        using var pubExp         = new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, new byte[] { 0x01, 0x00, 0x01 });
        using var pubModifiable  = new ObjectAttribute(CKA.CKA_MODIFIABLE, false);

        using var privClass      = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var privKeyType    = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA);
        using var privToken      = new ObjectAttribute(CKA.CKA_TOKEN, persistOnToken);
        using var privSensitive  = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var privExtract    = new ObjectAttribute(CKA.CKA_EXTRACTABLE, false);
        using var privDecrypt    = new ObjectAttribute(CKA.CKA_DECRYPT, true);
        using var privSign       = new ObjectAttribute(CKA.CKA_SIGN, true);
        using var privUnwrap     = new ObjectAttribute(CKA.CKA_UNWRAP, true);
        using var privModifiable = new ObjectAttribute(CKA.CKA_MODIFIABLE, false);

        var pubTemplate  = new List<ObjectAttribute> { pubClass, pubKeyType, pubToken, pubEncrypt, pubVerify, pubWrap, pubModBits, pubExp, pubModifiable };
        var privTemplate = new List<ObjectAttribute> { privClass, privKeyType, privToken, privSensitive, privExtract, privDecrypt, privSign, privUnwrap, privModifiable };

        if (label is not null)
        {
            using var pubLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            using var privLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            pubTemplate.Add(pubLabel);
            privTemplate.Add(privLabel);
            GenerateKeyPair(mechanism, pubTemplate, privTemplate, out var pub, out var priv);
            return (pub, priv);
        }

        GenerateKeyPair(mechanism, pubTemplate, privTemplate, out var pub2, out var priv2);
        return (pub2, priv2);
    }

    /// <summary>
    /// Generates an EC key pair on the named curve as session objects (private key
    /// non-extractable + sensitive, CKA_TOKEN=false).
    /// </summary>
    /// <param name="curve">Named curve — currently supports <see cref="EcCurve.P256"/>, <see cref="EcCurve.P384"/>, <see cref="EcCurve.P521"/>. Default P-256.</param>
    /// <param name="label">Optional CKA_LABEL applied to both keys.</param>
    /// <param name="persistOnToken">If true, both keys created with CKA_TOKEN=true. Default false.</param>
    /// <returns>(publicKeyHandle, privateKeyHandle) tuple.</returns>
    public (ObjectHandle pub, ObjectHandle priv) GenerateEcKeyPair(EcCurve curve = EcCurve.P256, string? label = null, bool persistOnToken = false)
    {
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        byte[] ecParams = curve switch
        {
            // prime256v1 (P-256): 1.2.840.10045.3.1.7
            EcCurve.P256 => new byte[] { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 },
            // secp384r1 (P-384): 1.3.132.0.34
            EcCurve.P384 => new byte[] { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 },
            // secp521r1 (P-521): 1.3.132.0.35
            EcCurve.P521 => new byte[] { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 },
            _ => throw new ArgumentOutOfRangeException(nameof(curve), $"Unsupported curve: {curve}."),
        };

        using var mechanism = new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN);

        using var pubClass       = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var pubKeyType     = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC);
        using var pubToken       = new ObjectAttribute(CKA.CKA_TOKEN, persistOnToken);
        using var pubVerify      = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var pubParams      = new ObjectAttribute(CKA.CKA_EC_PARAMS, ecParams);
        using var pubModifiable  = new ObjectAttribute(CKA.CKA_MODIFIABLE, false);
        using var pubEncrypt     = new ObjectAttribute(CKA.CKA_ENCRYPT, false);
        using var pubWrap        = new ObjectAttribute(CKA.CKA_WRAP, false);

        using var privClass      = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var privKeyType    = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC);
        using var privToken      = new ObjectAttribute(CKA.CKA_TOKEN, persistOnToken);
        using var privSensitive  = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var privExtract    = new ObjectAttribute(CKA.CKA_EXTRACTABLE, false);
        using var privSign       = new ObjectAttribute(CKA.CKA_SIGN, true);
        using var privDerive     = new ObjectAttribute(CKA.CKA_DERIVE, true);
        using var privModifiable = new ObjectAttribute(CKA.CKA_MODIFIABLE, false);

        var pubTemplate  = new List<ObjectAttribute> { pubClass, pubKeyType, pubToken, pubVerify, pubParams, pubModifiable, pubEncrypt, pubWrap };
        var privTemplate = new List<ObjectAttribute> { privClass, privKeyType, privToken, privSensitive, privExtract, privSign, privDerive, privModifiable };

        if (label is not null)
        {
            using var pubLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            using var privLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            pubTemplate.Add(pubLabel);
            privTemplate.Add(privLabel);
            GenerateKeyPair(mechanism, pubTemplate, privTemplate, out var pub, out var priv);
            return (pub, priv);
        }

        GenerateKeyPair(mechanism, pubTemplate, privTemplate, out var pub2, out var priv2);
        return (pub2, priv2);
    }
}
