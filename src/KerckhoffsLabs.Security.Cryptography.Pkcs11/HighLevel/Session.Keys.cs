using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

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
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::GenerateKey", _sessionId);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

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
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_GenerateKey", rv);

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
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::GenerateKeyPair", _sessionId);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

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
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_GenerateKeyPair", rv);

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
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::WrapKey", _sessionId);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (wrappingKeyHandle == null)
            throw new ArgumentNullException("wrappingKeyHandle");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        NativeCULong wrappedKeyLen = (NativeCULong)0;
        CKR rv = _pkcs11Library.C_WrapKey(_sessionId, ref ckMechanism, (NativeCULong)(wrappingKeyHandle.ObjectId), (NativeCULong)(keyHandle.ObjectId), null, ref wrappedKeyLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_WrapKey", rv);

        byte[] wrappedKey = new byte[(int)wrappedKeyLen];
        rv = _pkcs11Library.C_WrapKey(_sessionId, ref ckMechanism, (NativeCULong)(wrappingKeyHandle.ObjectId), (NativeCULong)(keyHandle.ObjectId), wrappedKey, ref wrappedKeyLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_WrapKey", rv);

        if (wrappedKey.Length != (int)(wrappedKeyLen))
            Array.Resize(ref wrappedKey, (int)(wrappedKeyLen));

        return wrappedKey;
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
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::UnwrapKey", _sessionId);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (unwrappingKeyHandle == null)
            throw new ArgumentNullException("unwrappingKeyHandle");

        if (wrappedKey == null)
            throw new ArgumentNullException("wrappedKey");

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
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_UnwrapKey", rv);

        return new ObjectHandle((ulong)unwrappedKey);
    }
}
