namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// A mechanism parameter block already written into a call's scope: what <c>CK_MECHANISM.pParameter</c>
/// and <c>ulParameterLen</c> receive.
/// </summary>
/// <param name="Pointer">Address of the block, owned by the call's scope. <see cref="IntPtr.Zero"/> when there is none.</param>
/// <param name="Length">Length of the block in bytes.</param>
internal readonly record struct Pkcs11ParameterBlock(IntPtr Pointer, int Length)
{
    /// <summary>
    /// Reads the block back as <typeparamref name="T"/>, as the token left it. Only valid while the
    /// scope that owns it is alive.
    /// </summary>
    public T Read<T>() where T : unmanaged => UnmanagedMemory.Read<T>(Pointer);
}
