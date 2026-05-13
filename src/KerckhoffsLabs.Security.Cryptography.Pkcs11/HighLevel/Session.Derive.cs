using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel.MechanismParams;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public partial class Session
{
    /// <summary>
    /// Derives a key from a base key, creating a new key object
    /// </summary>
    /// <param name="mechanism">Derivation mechanism</param>
    /// <param name="baseKeyHandle">Handle of base key</param>
    /// <param name="attributes">Attributes for the new key</param>
    /// <returns>Handle of derived key</returns>
    public ObjectHandle DeriveKey(Mechanism mechanism, ObjectHandle baseKeyHandle, List<ObjectAttribute> attributes)
    {
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (baseKeyHandle == null)
            throw new ArgumentNullException("baseKeyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.LogDebug("Session({SessionId})::DeriveKey", _sessionId);

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

        NativeCULong derivedKey = CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_DeriveKey(_sessionId, ref ckMechanism, (NativeCULong)(baseKeyHandle.ObjectId), template, templateLen, ref derivedKey);
        Pkcs11Exception.ThrowIfError(rv, "C_DeriveKey");

        return new ObjectHandle((ulong)derivedKey);
    }

    // === Secure-default derive helpers =====================================

    /// <summary>
    /// Performs ECDH1 key derivation using the caller's EC private key and the peer's public
    /// point. The derived key is an AES secret key — session-only, sensitive, non-extractable,
    /// non-modifiable — suitable for use with AES-GCM. Defaults to 32 bytes with the SHA-256 KDF;
    /// pass <paramref name="aesBitLength"/> to change the AES key length.
    /// </summary>
    /// <param name="myPrivateKeyHandle">Handle of the caller's EC private key (CKA_DERIVE=true).</param>
    /// <param name="peerPublicPoint">DER-encoded OCTET STRING of the peer's public EC point (the full <c>CKA_EC_POINT</c> attribute value).</param>
    /// <param name="aesBitLength">Derived AES key length in bits — 128, 192, or 256. Default 256.</param>
    /// <returns>Handle of the derived AES key.</returns>
    public ObjectHandle DeriveSharedSecretEcdh(ObjectHandle myPrivateKeyHandle, ReadOnlySpan<byte> peerPublicPoint, int aesBitLength = 256)
    {
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (myPrivateKeyHandle == null)
            throw new ArgumentNullException(nameof(myPrivateKeyHandle));

        if (aesBitLength != 128 && aesBitLength != 192 && aesBitLength != 256)
            throw new ArgumentOutOfRangeException(nameof(aesBitLength), "AES key length must be 128, 192, or 256 bits.");

        using var p = new CkmEcdh1DeriveParams(CKD.CKD_SHA256_KDF, peerPublicPoint);
        using var mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, p);

        using var attrClass      = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrKeyType    = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
        using var attrValueLen   = new ObjectAttribute(CKA.CKA_VALUE_LEN, (ulong)(aesBitLength / 8));
        using var attrToken      = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrSensitive  = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var attrExtract    = new ObjectAttribute(CKA.CKA_EXTRACTABLE, false);
        using var attrEncrypt    = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
        using var attrDecrypt    = new ObjectAttribute(CKA.CKA_DECRYPT, true);
        using var attrModifiable = new ObjectAttribute(CKA.CKA_MODIFIABLE, false);

        var template = new List<ObjectAttribute> { attrClass, attrKeyType, attrValueLen, attrToken, attrSensitive, attrExtract, attrEncrypt, attrDecrypt, attrModifiable };
        return DeriveKey(mechanism, myPrivateKeyHandle, template);
    }
}
