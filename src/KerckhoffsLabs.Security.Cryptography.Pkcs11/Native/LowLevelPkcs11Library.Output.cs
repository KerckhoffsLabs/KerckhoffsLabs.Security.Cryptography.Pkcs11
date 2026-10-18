using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

// The rules every wrapper with an output buffer follows (PKCS#11 v3.2 §5.2).
internal sealed partial class LowLevelPkcs11Library
{
    // What an empty output buffer is pinned to. `fixed` over an empty span yields NULL, which a module
    // takes as a length query: a real zero-length output, such as a final with nothing left to emit,
    // would then leave the operation active. A real location gives it an address the module, told
    // the buffer holds zero bytes, never writes through.
    private static byte s_emptyOutput;

    /// <summary>
    /// The reference to pin for <paramref name="output"/>: its first byte, or a real static location when
    /// it is empty. Never a null reference, so only <c>lengthOnly</c> sends the module a NULL buffer.
    /// </summary>
    private static ref byte NonNullPinnable(Span<byte> output)
        => ref output.IsEmpty ? ref s_emptyOutput : ref MemoryMarshal.GetReference(output);

    /// <summary>
    /// The same for an input, where an empty span is still real (empty) data. Every data, part and
    /// signature input is pinned this way: SoftHSM2, Kryoptic and opencryptoki reject <c>pData == NULL</c>
    /// with CKR_ARGUMENTS_BAD even when the length is zero, and SoftHSM2 does so from C_Digest, C_Sign
    /// and C_Verify without ending the operation.
    /// </summary>
    private static ref byte NonNullPinnable(ReadOnlySpan<byte> input)
        => ref input.IsEmpty ? ref s_emptyOutput : ref MemoryMarshal.GetReference(input);

    /// <summary>
    /// Refuses a C string argument whose last byte is not its NUL. The module is given only the pointer and
    /// reads up to the first NUL, so without one inside the span it would read past the caller's memory.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="value"/> is empty or does not end in a NUL.</exception>
    private static void RequireNulTerminated(ReadOnlySpan<byte> value, string paramName)
    {
        if (value.IsEmpty || value[^1] != 0)
            throw new ArgumentException("A C string argument must end in its NUL terminator: the module reads up to it.", paramName);
    }

    /// <summary>
    /// Checks the length a module reported for an output before any caller sees it. A length query must
    /// report a length that can be allocated (never <c>CK_UNAVAILABLE_INFORMATION</c>); a fill must
    /// report no more than the buffer it was given. Either violation throws rather than letting a
    /// caller pad, truncate or overrun.
    /// </summary>
    /// <returns><paramref name="rv"/>, unchanged.</returns>
    private static CKR CheckedOutput(CKR rv, bool lengthOnly, NativeCULong reported, int capacity, [CallerMemberName] string function = "")
    {
        if (rv == CKR.CKR_OK)
        {
            if (lengthOnly)
                ReportedLength.ForAllocation(reported, function);
            else
                ReportedLength.Written(reported, capacity, function);
        }
        return rv;
    }
}
