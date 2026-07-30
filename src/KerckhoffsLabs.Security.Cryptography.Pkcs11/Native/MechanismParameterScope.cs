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
    private bool _disposed;

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
    public IntPtr WriteStruct<T>(in T value) where T : struct
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        IntPtr p = Allocate(UnmanagedMemory.SizeOf<T>());
        UnmanagedMemory.Write(p, in value);
        return p;
    }

    /// <summary>Marshals a contiguous array of structs into a new block owned by this scope.</summary>
    public IntPtr WriteStructArray<T>(ReadOnlySpan<T> values) where T : struct
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
