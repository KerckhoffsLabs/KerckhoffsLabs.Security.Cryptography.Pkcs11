using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Token-specific identifier for an object returned by the PKCS#11 module.
/// </summary>
/// <remarks>
/// Instances are produced exclusively by <see cref="Session"/> factory methods
/// (<c>FindObjects</c>, <c>GenerateKey</c>, <c>GenerateKeyPair</c>, <c>CreateObject</c>,
/// <c>DeriveKey</c>, <c>UnwrapKey</c>). The constructors are <c>internal</c> so external
/// code cannot fabricate a handle with an arbitrary <see cref="ObjectId"/> and feed it
/// to a session — that would either fail with <c>CKR_OBJECT_HANDLE_INVALID</c> at the
/// PKCS#11 boundary or, worse, act on an unrelated object that happens to share the
/// integer ID. The internal constructor remains visible to the test assembly via
/// <c>InternalsVisibleTo</c> for tests that build a fake handle (e.g. handle <c>0</c>)
/// to drive negative-path assertions.
/// </remarks>
public sealed class ObjectHandle
{
    /// <summary>
    /// PKCS#11 handle of the object.
    /// </summary>
    private readonly NativeCULong _objectId = CK.CK_INVALID_HANDLE;

    /// <summary>
    /// PKCS#11 handle of the object.
    /// </summary>
    public ulong ObjectId => (ulong)_objectId;

    /// <summary>
    /// Initializes a new instance with <see cref="ObjectId"/> set to
    /// <see cref="CK.CK_INVALID_HANDLE"/>.
    /// </summary>
    internal ObjectHandle()
    {
        _objectId = CK.CK_INVALID_HANDLE;
    }

    /// <summary>
    /// Initializes a new instance wrapping the given PKCS#11 object handle.
    /// </summary>
    /// <param name="objectId">PKCS#11 handle of the object.</param>
    internal ObjectHandle(ulong objectId)
    {
        _objectId = (NativeCULong)objectId;
    }
}