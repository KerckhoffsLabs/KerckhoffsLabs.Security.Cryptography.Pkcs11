using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support;

/// <summary>
/// Raw parameter blocks for <see cref="Mechanism"/>: zeros of a length it takes, for the cases that pass one
/// only to see what a policy or a check makes of a parameter it cannot read, and a <c>CK_*_PARAMS</c> struct
/// laid out by the test, for the cases that send a module a value the library's parameter types refuse.
/// </summary>
internal static class RawParameter
{
    /// <summary>The layout's size on this platform where the mechanism has one, 16 bytes where it does not.</summary>
    internal static byte[] Of(CKM type)
        => new byte[MechanismParameterLength.For(type) is { } rule ? rule.Lengths.First(length => length > 0) : 16];

    /// <summary>
    /// The struct as this platform lays it out (packed on Windows, natural elsewhere), as the mechanism's raw
    /// parameter. Its pointers are the caller's to keep valid until the call returns (see <see cref="NativeBuffers"/>).
    /// </summary>
    internal static Mechanism From<T>(CKM type, in T parameter) where T : unmanaged
    {
        byte[] block = new byte[Pkcs11Marshal.SizeOf<T>()];
        IntPtr buffer = Marshal.AllocHGlobal(block.Length);
        try
        {
            Pkcs11Marshal.WriteStructure(buffer, in parameter);
            Marshal.Copy(buffer, block, 0, block.Length);
        }
        finally { Marshal.FreeHGlobal(buffer); }
        return new Mechanism(type, block);
    }
}

/// <summary>Unmanaged copies of the buffers a raw parameter block points at, freed when disposed.</summary>
internal sealed class NativeBuffers : IDisposable
{
    private readonly List<IntPtr> _buffers = [];

    public IntPtr Of(byte[] data)
    {
        IntPtr buffer = Marshal.AllocHGlobal(Math.Max(data.Length, 1));
        _buffers.Add(buffer);
        Marshal.Copy(data, 0, buffer, data.Length);
        return buffer;
    }

    public void Dispose()
    {
        foreach (IntPtr buffer in _buffers)
            Marshal.FreeHGlobal(buffer);
        _buffers.Clear();
    }
}
