using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal sealed partial class Pkcs11Session
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
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);

        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "GenerateKey");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CK_ATTRIBUTE[]? template = null;
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
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);

        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "GenerateKeyPair");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CK_ATTRIBUTE[]? publicKeyTemplate = null;
        NativeCULong publicKeyTemplateLength = (NativeCULong)0;

        if (publicKeyAttributes != null)
        {
            publicKeyTemplateLength = (NativeCULong)(publicKeyAttributes.Count);
            publicKeyTemplate = new CK_ATTRIBUTE[(int)publicKeyTemplateLength];
            for (int i = 0; i < (int)(publicKeyTemplateLength); i++)
                publicKeyTemplate[i] = publicKeyAttributes[i].CkAttribute;
        }

        CK_ATTRIBUTE[]? privateKeyTemplate = null;
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
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);


        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "WrapKey");

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
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
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
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);


        ArgumentNullException.ThrowIfNull(wrappedKey);

        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "UnwrapKey");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        // Unwrapping decrypts a key blob into a new token object. Without secure defaults a caller
        // could land an extractable, non-sensitive key — silently downgrading the posture the key
        // template builders establish. Append CKA_SENSITIVE=true / CKA_EXTRACTABLE=false when the
        // caller omitted them; an explicit insecure value requires AllowInsecure (throws otherwise).
        List<ObjectAttribute> secureDefaults = BuildSecureUnwrapDefaults(attributes);
        try
        {
            int attrCount = attributes?.Count ?? 0;
            int total = attrCount + secureDefaults.Count;
            CK_ATTRIBUTE[]? template = total > 0 ? new CK_ATTRIBUTE[total] : null;
            NativeCULong templateLen = (NativeCULong)0;
            if (template != null)
            {
                int idx = 0;
                for (int i = 0; i < attrCount; i++)
                    template[idx++] = attributes![i].CkAttribute;
                foreach (ObjectAttribute d in secureDefaults)
                    template[idx++] = d.CkAttribute;
                templateLen = (NativeCULong)total;
            }

            NativeCULong unwrappedKey = CK.CK_INVALID_HANDLE;
            CKR rv = _pkcs11Library.C_UnwrapKey(_sessionId, ref ckMechanism, (NativeCULong)(unwrappingKeyHandle.ObjectId), wrappedKey, (NativeCULong)(wrappedKey.Length), template, templateLen, ref unwrappedKey);
            Pkcs11Exception.ThrowIfError(rv, "C_UnwrapKey");

            return new ObjectHandle((ulong)unwrappedKey);
        }
        finally
        {
            foreach (ObjectAttribute d in secureDefaults)
                d.Dispose();
        }
    }

    /// <summary>
    /// Returns the secure-default attributes (<c>CKA_SENSITIVE=true</c> / <c>CKA_EXTRACTABLE=false</c>)
    /// to append to an unwrap template for any the caller omitted. If the caller supplied an explicit
    /// insecure value (<c>CKA_SENSITIVE=false</c> or <c>CKA_EXTRACTABLE=true</c>), it is permitted only
    /// when <see cref="AllowInsecure"/> is set; otherwise <see cref="InsecureOperationException"/> is
    /// thrown. The returned attributes own unmanaged buffers and must be disposed by the caller.
    /// </summary>
    private List<ObjectAttribute> BuildSecureUnwrapDefaults(List<ObjectAttribute>? attributes)
    {
        bool hasSensitive = false;
        bool hasExtractable = false;

        if (attributes != null)
        {
            foreach (ObjectAttribute a in attributes)
            {
                if (a.Type == (ulong)CKA.CKA_SENSITIVE)
                {
                    hasSensitive = true;
                    if (!a.GetValueAsBool() && !AllowInsecure)
                        throw new InsecureOperationException(
                            "UnwrapKey with CKA_SENSITIVE=false would create a non-sensitive key whose value can be read off the token. " +
                            "Pass AllowInsecure (or use AllowInsecureScope) to override.");
                }
                else if (a.Type == (ulong)CKA.CKA_EXTRACTABLE)
                {
                    hasExtractable = true;
                    if (a.GetValueAsBool() && !AllowInsecure)
                        throw new InsecureOperationException(
                            "UnwrapKey with CKA_EXTRACTABLE=true would create an extractable key. " +
                            "Pass AllowInsecure (or use AllowInsecureScope) to override.");
                }
            }
        }

        List<ObjectAttribute> added = [];
        if (!hasSensitive)
            added.Add(new ObjectAttribute(CKA.CKA_SENSITIVE, true));
        if (!hasExtractable)
            added.Add(new ObjectAttribute(CKA.CKA_EXTRACTABLE, false));
        return added;
    }
}
