// Licensed under the MIT License

using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Token-specific identifier for an object returned by the PKCS#11 module.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ObjectHandle"/> is a strongly-typed, allocation-free wrapper around
/// a single <c>CK_OBJECT_HANDLE</c> integer. The shape follows the BCL pattern used
/// by opaque identity types like <c>System.Diagnostics.ActivitySpanId</c> — a
/// <c>readonly record struct</c> wrapping the underlying integer, with value
/// equality and no heap allocation.
/// </para>
/// <para>
/// Instances are produced exclusively by <see cref="Session"/> factory methods
/// (<c>FindObjects</c>, <c>GenerateKey</c>, <c>GenerateKeyPair</c>, <c>CreateObject</c>,
/// <c>DeriveKey</c>, <c>UnwrapKey</c>). The constructor is <c>internal</c> so external
/// code cannot fabricate a handle with an arbitrary <see cref="ObjectId"/> and feed it
/// to a session — that would either fail with <c>CKR_OBJECT_HANDLE_INVALID</c> at the
/// PKCS#11 boundary or, worse, act on an unrelated object that happens to share the
/// integer ID. The internal constructor remains visible to the test assembly via
/// <c>InternalsVisibleTo</c> for tests that build a fake handle to drive negative-path
/// assertions.
/// </para>
/// <para>
/// <c>default(ObjectHandle)</c> equals <see cref="Invalid"/> — the underlying integer
/// is <c>0</c>, which is <see cref="CK.CK_INVALID_HANDLE"/>. Callers can safely use
/// <c>default</c> as a sentinel and check <see cref="IsInvalid"/>.
/// </para>
/// </remarks>
public readonly record struct ObjectHandle
{
    /// <summary>
    /// PKCS#11 handle of the object.
    /// </summary>
    private readonly NativeCULong _objectId;

    /// <summary>
    /// Initializes a new instance wrapping the given PKCS#11 object handle.
    /// </summary>
    /// <param name="objectId">PKCS#11 handle of the object.</param>
    internal ObjectHandle(ulong objectId)
    {
        _objectId = (NativeCULong)objectId;
    }

    /// <summary>
    /// PKCS#11 handle of the object as an unsigned 64-bit integer.
    /// </summary>
    public ulong ObjectId => (ulong)_objectId;

    /// <summary>
    /// The invalid-handle sentinel (<see cref="CK.CK_INVALID_HANDLE"/>). Equal to <c>default(ObjectHandle)</c>.
    /// </summary>
    public static ObjectHandle Invalid => default;

    /// <summary>
    /// <c>true</c> when this handle equals <see cref="CK.CK_INVALID_HANDLE"/> (i.e. <c>default</c>).
    /// </summary>
    public bool IsInvalid => _objectId == CK.CK_INVALID_HANDLE;

    /// <inheritdoc />
    public override string ToString() => $"ObjectHandle(0x{ObjectId:X})";
}
