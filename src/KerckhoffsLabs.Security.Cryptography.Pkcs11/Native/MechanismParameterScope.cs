using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Owns every unmanaged byte a single PKCS#11 call needs for its mechanism parameters: the
/// <c>CK_MECHANISM</c> block and any buffers its pointer fields address.
/// </summary>
/// <remarks>
/// The lifetime is the call, not the parameter object. That is what lets <c>Ckm*Params</c> hold
/// managed data only — nothing survives the operation, so nothing needs an owner, a disposal order,
/// or a rule against sharing one instance across two mechanisms.
/// Allocation goes through <see cref="UnmanagedMemory"/>, so every block is tracked by the leak
/// harness and zeroized as it is freed.
/// </remarks>
internal sealed class MechanismParameterScope : IDisposable
{
    private readonly List<IntPtr> _owned = [];
    private readonly Pkcs11Session? _session;
    private bool _disposed;

    /// <summary>Creates a scope for a call made on <paramref name="session"/>.</summary>
    /// <param name="session">
    /// The session performing the call. Needed only to resolve key-valued parameters; a scope without
    /// one can marshal everything else.
    /// </param>
    public MechanismParameterScope(Pkcs11Session? session = null) => _session = session;

    /// <summary>
    /// The handle <paramref name="key"/> contributes to a parameter field, checked against the session
    /// performing this call.
    /// </summary>
    /// <param name="key">The key the caller put in the parameter.</param>
    /// <param name="part">Which of the key's objects the field refers to.</param>
    /// <param name="paramName">The parameter-type argument the key was passed as, for the exception.</param>
    /// <exception cref="ObjectDisposedException">The key has been disposed.</exception>
    /// <exception cref="ArgumentException">The key belongs to another workspace, or lacks the requested object.</exception>
    /// <exception cref="InvalidOperationException">The scope was created without a session.</exception>
    public NativeCULong KeyHandle(Pkcs11Key key, KeyHandlePart part, string paramName)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_session is null)
            throw new InvalidOperationException("Key-valued mechanism parameters can only be marshalled for a session.");
        return (NativeCULong)key.ResolveParameterHandle(_session, part, paramName).ObjectId;
    }

    /// <summary>Allocates <paramref name="size"/> zeroed bytes owned by this scope.</summary>
    public IntPtr Allocate(int size)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (size <= 0) return IntPtr.Zero;

        IntPtr p = UnmanagedMemory.Allocate(size);
        _owned.Add(p);
        return p;
    }

    /// <summary>Copies <paramref name="bytes"/> into a new block owned by this scope.</summary>
    /// <returns><see cref="IntPtr.Zero"/> for an empty span, which is what PKCS#11 expects for an absent buffer.</returns>
    public IntPtr Write(ReadOnlySpan<byte> bytes)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (bytes.IsEmpty) return IntPtr.Zero;

        IntPtr p = Allocate(bytes.Length);
        UnmanagedMemory.Write(p, bytes);
        return p;
    }

    /// <summary>Marshals a single struct into a new block owned by this scope.</summary>
    public IntPtr WriteStruct<T>(in T value) where T : unmanaged
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        IntPtr p = Allocate(UnmanagedMemory.SizeOf<T>());
        UnmanagedMemory.Write(p, in value);
        return p;
    }

    /// <summary>
    /// Writes a mechanism's parameter struct into a new block owned by this scope, in the platform's
    /// layout, and returns it with its length.
    /// </summary>
    public Pkcs11ParameterBlock WriteParameter<T>(in T value) where T : unmanaged
        => new(WriteStruct(in value), UnmanagedMemory.SizeOf<T>());

    /// <summary>Marshals a contiguous array of structs into a new block owned by this scope.</summary>
    public IntPtr WriteStructArray<T>(ReadOnlySpan<T> values) where T : unmanaged
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (values.IsEmpty) return IntPtr.Zero;

        int size = UnmanagedMemory.SizeOf<T>();
        IntPtr p = Allocate(size * values.Length);
        for (int i = 0; i < values.Length; i++)
            UnmanagedMemory.Write(IntPtr.Add(p, i * size), in values[i]);
        return p;
    }

    /// <summary>Releases every block, newest first. <see cref="UnmanagedMemory.Free"/> zeroizes as it goes.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        for (int i = _owned.Count - 1; i >= 0; i--)
        {
            IntPtr p = _owned[i];
            UnmanagedMemory.Free(ref p);
        }
        _owned.Clear();
        _disposed = true;
    }
}
