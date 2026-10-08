namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// An array of PKCS#11 structs (an attribute template, an interface list) laid out for one call in the
/// layout the module reads: Pack=1 on Windows, natural elsewhere (see <see cref="Pkcs11Marshal"/>).
/// Dispatch code passes <see cref="Pointer"/> and <see cref="Count"/> the same way on every platform, and
/// reads what the module wrote back with <see cref="CopyTo"/>.
/// </summary>
/// <remarks>
/// The block comes from <see cref="UnmanagedMemory"/>, so the leak harness tracks it and it is zeroized
/// when freed.
/// </remarks>
/// <typeparam name="T">The unified struct type.</typeparam>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S6640:Using unsafe code blocks is security-sensitive",
    Justification = "This type hands a module the address of a block it owns, which C# exposes only as a raw "
    + "pointer in unsafe code. The block is sized from Pkcs11Marshal.SizeOf for the layout it is written in, "
    + "written and read only through Pkcs11Marshal, and freed on Dispose. Suppressed at the type so the rule "
    + "keeps its value elsewhere.")]
internal unsafe ref struct NativeStructArray<T> : IDisposable
    where T : unmanaged
{
    private readonly int _count;
    private readonly int _stride;
    private readonly bool _windowsLayout;
    private IntPtr _block;

    /// <summary>Lays <paramref name="items"/> out in this platform's layout.</summary>
    /// <param name="items">The structs, in order.</param>
    /// <param name="nullWhenEmpty">
    /// Whether an empty array is passed as NULL. True for an attribute template, where NULL with a count of
    /// 0 is a legitimate Cryptoki argument. False for a list the module fills, where NULL would ask for the
    /// count instead: the module is then given a real address it is told holds no entries.
    /// </param>
    public NativeStructArray(ReadOnlySpan<T> items, bool nullWhenEmpty)
        : this(items, nullWhenEmpty, Pkcs11Marshal.IsWindows)
    {
    }

    /// <summary>Lays <paramref name="items"/> out in an explicit layout, so either can be checked on any OS.</summary>
    internal NativeStructArray(ReadOnlySpan<T> items, bool nullWhenEmpty, bool windowsLayout)
    {
        _count = items.Length;
        _stride = Pkcs11Marshal.SizeOf<T>(windowsLayout);
        _windowsLayout = windowsLayout;
        if (_count == 0 && nullWhenEmpty)
            return;

        _block = UnmanagedMemory.Allocate(checked(_stride * Math.Max(_count, 1)));
        for (int i = 0; i < _count; i++)
            Pkcs11Marshal.WriteStructure(_block + i * _stride, in items[i], windowsLayout);
    }

    /// <summary>The first struct, or NULL for an empty array built with <c>nullWhenEmpty</c>.</summary>
    public readonly void* Pointer => (void*)_block;

    /// <summary>The number of structs, as the module's count argument.</summary>
    public readonly NativeCULong Count => (NativeCULong)_count;

    /// <summary>Reads each struct back, as the module left it, into <paramref name="items"/>.</summary>
    public readonly void CopyTo(Span<T> items)
    {
        for (int i = 0; i < _count; i++)
            items[i] = Pkcs11Marshal.ReadStructure<T>(_block + i * _stride, _windowsLayout);
    }

    /// <summary>Frees the block.</summary>
    public void Dispose() => UnmanagedMemory.Free(ref _block);
}
