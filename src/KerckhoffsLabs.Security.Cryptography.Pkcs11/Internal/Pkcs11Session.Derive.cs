using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal sealed partial class Pkcs11Session
{
    /// <summary>
    /// Derives a key from a base key, creating a new key object. Secure defaults
    /// (<c>CKA_SENSITIVE=true</c> / <c>CKA_EXTRACTABLE=false</c>) are applied to the result template;
    /// an explicit insecure value requires <see cref="AllowInsecure"/>.
    /// </summary>
    /// <param name="mechanism">Derivation mechanism</param>
    /// <param name="baseKeyHandle">Handle of base key</param>
    /// <param name="attributes">Attributes for the new key</param>
    /// <returns>Handle of derived key</returns>
    public ObjectHandle DeriveKey(Mechanism mechanism, ObjectHandle baseKeyHandle, List<ObjectAttribute> attributes)
        => DeriveKey(mechanism, baseKeyHandle, attributes, enforceSecureDefaults: true);

    /// <summary>
    /// Derive implementation. When <paramref name="enforceSecureDefaults"/> is <c>false</c> the caller's
    /// template is passed to <c>C_DeriveKey</c> verbatim, bypassing the secure-default gate. This is for
    /// the library's own extract-and-destroy helpers (ECDH raw shared secret, SP800-108 raw KDF output)
    /// that deliberately derive an ephemeral extractable secret, read <c>CKA_VALUE</c>, then destroy it —
    /// where the gate would otherwise reject a legitimate, non-persistent operation. Not public.
    /// </summary>
    internal ObjectHandle DeriveKey(Mechanism mechanism, ObjectHandle baseKeyHandle, List<ObjectAttribute> attributes, bool enforceSecureDefaults)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);


        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DeriveKey");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        // Deriving produces a new key object on the token. Apply the same secure defaults as UnwrapKey
        // (CKA_SENSITIVE=true / CKA_EXTRACTABLE=false when the caller omitted them); an explicit insecure
        // value requires AllowInsecure (throws otherwise). See BuildSecureKeyDefaults. Trusted internal
        // extract-and-destroy callers pass enforceSecureDefaults=false and supply the template verbatim.
        List<ObjectAttribute> secureDefaults = enforceSecureDefaults ? BuildSecureKeyDefaults(attributes) : [];
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

            NativeCULong derivedKey = CK.CK_INVALID_HANDLE;
            CKR rv = _pkcs11Library.C_DeriveKey(_sessionId, ref ckMechanism, (NativeCULong)(baseKeyHandle.ObjectId), template, templateLen, ref derivedKey);
            Pkcs11Exception.ThrowIfError(rv, "C_DeriveKey");

            return new ObjectHandle((ulong)derivedKey);
        }
        finally
        {
            foreach (ObjectAttribute d in secureDefaults)
                d.Dispose();
        }
    }
}
