using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal sealed partial class Pkcs11Session
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
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);


        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DeriveKey");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CK_ATTRIBUTE[]? template = null;
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
}
