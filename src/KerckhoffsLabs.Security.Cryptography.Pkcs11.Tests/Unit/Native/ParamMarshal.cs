using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// Shared round-trip helper for the mechanism-parameter marshal tests: writes the boxed low-level
/// <c>CK_*</c> struct through the platform marshaller and reads it back. Pointers in the result
/// reference the scope the struct was built into, so callers keep that scope alive while
/// dereferencing them.
/// </summary>
internal static class ParamMarshal
{
    public static T RoundTrip<T>(object raw) where T : unmanaged
    {
        int size = UnmanagedMemory.SizeOf<T>();
        IntPtr mem = UnmanagedMemory.Allocate(size);
        try
        {
            UnmanagedMemory.Write(mem, raw);
            return UnmanagedMemory.Read<T>(mem);
        }
        finally { UnmanagedMemory.Free(ref mem); }
    }
}
