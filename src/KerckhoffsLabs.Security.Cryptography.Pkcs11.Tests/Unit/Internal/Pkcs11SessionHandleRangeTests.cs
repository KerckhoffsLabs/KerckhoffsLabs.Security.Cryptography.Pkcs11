using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.SafeHandles;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

// CK_SESSION_HANDLE is an opaque CK_ULONG: every value in its unsigned range is legal, and modules
// that derive handles from pointers or hash tables really do set the high bit. Nothing about the
// handle is a pointer, so it must never be routed through IntPtr — that type is signed and
// pointer-width, and this assembly builds with CheckForOverflowUnderflow, so the top half of the
// range would throw on conversion. Nor may it be truncated: a silently narrowed handle would be
// handed back to the module as a different, possibly live, session.
//
// Failing that way is worse than it sounds. The throw lands in the constructor before the session is
// registered, leaving handle zero, so IsInvalid reports true, ReleaseHandle no-ops, and the session
// just opened on the token is never closed for the lifetime of the process.
public sealed class Pkcs11SessionHandleRangeTests
{
    private sealed class ClosingLibrary : NotSupportedPkcs11Library
    {
        public NativeCULong? Closed;
        public override CKR C_CloseSession(NativeCULong session)
        {
            Closed = session;
            return CKR.CKR_OK;
        }
    }

    // The whole range a CK_ULONG can hold on this RID, high bit included. NativeCULong is 32-bit on
    // Windows and pointer-width elsewhere, so the boundary cases are computed rather than hardcoded.
    public static TheoryData<ulong> HandleValues()
    {
        ulong max = UnmanagedMemory.NativeULongSize == sizeof(uint) ? uint.MaxValue : ulong.MaxValue;
        return [1UL, 42UL, (max >> 1) + 1, max - 1, max];
    }

    [Theory]
    [MemberData(nameof(HandleValues))]
    public void SessionId_RoundTripsAcrossTheWholeCkUlongRange(ulong sessionId)
    {
        using var library = new ClosingLibrary();
        using var handle = new Pkcs11SessionHandle(library, (NativeCULong)sessionId);

        Assert.Equal(sessionId, (ulong)handle.SessionId);
        Assert.False(handle.IsInvalid);
    }

    // The value the reviewer's repro named: the first handle with the high bit set on a 64-bit RID.
    [Fact]
    public void HighBitHandle_IsRegisteredAndClosed_NotOrphaned()
    {
        ulong max = UnmanagedMemory.NativeULongSize == sizeof(uint) ? uint.MaxValue : ulong.MaxValue;
        ulong highBit = (max >> 1) + 2;

        using var library = new ClosingLibrary();
        var handle = new Pkcs11SessionHandle(library, (NativeCULong)highBit);

        Assert.False(handle.IsInvalid);
        handle.Dispose();

        // Not merely "did not throw": the session actually reached C_CloseSession, with its id intact.
        Assert.Equal(highBit, (ulong?)library.Closed);
    }

    [Fact]
    public void InvalidHandle_ReportsInvalid_AndIsNeverClosed()
    {
        using var library = new ClosingLibrary();
        var handle = new Pkcs11SessionHandle(library, (NativeCULong)CK.CK_INVALID_HANDLE);

        Assert.True(handle.IsInvalid);
        handle.Dispose();

        Assert.Null(library.Closed);
    }
}
