using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.SafeHandles;

/// <summary>
/// <see cref="SafeHandle"/> wrapper for a PKCS#11 native module loaded via
/// <see cref="NativeLibrary.Load(string)"/>. Releases via <see cref="NativeLibrary.Free(IntPtr)"/>.
/// </summary>
/// <remarks>
/// SafeHandle inherits from <c>CriticalFinalizerObject</c>, so release runs even on
/// <c>Environment.FailFast</c> and during AppDomain unload — better protection against
/// native-handle leaks than a regular finalizer.
/// </remarks>
internal sealed class Pkcs11ModuleHandle : SafeHandle
{
    /// <summary>Creates an invalid handle. Used as a sentinel before <see cref="NativeLibrary.Load(string)"/>.</summary>
    public Pkcs11ModuleHandle() : base(IntPtr.Zero, ownsHandle: true) { }

    /// <summary>Creates a handle that owns <paramref name="moduleHandle"/>.</summary>
    public Pkcs11ModuleHandle(IntPtr moduleHandle) : base(IntPtr.Zero, ownsHandle: true)
    {
        SetHandle(moduleHandle);
    }

    /// <inheritdoc/>
    public override bool IsInvalid => handle == IntPtr.Zero;

    /// <inheritdoc/>
    protected override bool ReleaseHandle()
    {
        if (handle == IntPtr.Zero) return true;
        try
        {
            NativeLibrary.Free(handle);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
