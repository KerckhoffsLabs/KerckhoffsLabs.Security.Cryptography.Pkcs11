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
