using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// Hermetic coverage for Pkcs11Library.WaitForSlotEvent — untouched by every other suite, since
/// nothing else in this project's test matrix generates a real slot event. Pins the
/// CKF_DONT_BLOCK flag encoding, the CKR_NO_EVENT non-blocking no-op, the event-occurred path,
/// error propagation, and the disposed guard.
/// </summary>
public sealed class WaitForSlotEventTests
{
    private sealed class SlotEventFake : NotSupportedPkcs11Library
    {
        public NativeCULong CapturedFlags;
        public CKR Rv = CKR.CKR_OK;
        public ulong SlotIdToReport = 3;

        public override CKR C_Initialize(CK_C_INITIALIZE_ARGS? initArgs) => CKR.CKR_OK;
        public override CKR C_Finalize(IntPtr reserved) => CKR.CKR_OK;

        public override CKR C_WaitForSlotEvent(NativeCULong flags, ref NativeCULong slot, IntPtr reserved)
        {
            CapturedFlags = flags;
            if (Rv == CKR.CKR_OK)
                slot = (NativeCULong)SlotIdToReport;
            return Rv;
        }
    }

    [Fact]
    public void EventOccurred_ReportsSlotId()
    {
        var fake = new SlotEventFake { Rv = CKR.CKR_OK, SlotIdToReport = 5 };
        using var library = new Pkcs11Library(fake);

        ulong? slotId = library.WaitForSlotEvent(nonBlocking: false);

        Assert.Equal(5UL, slotId);
        Assert.Equal((NativeCULong)0, fake.CapturedFlags); // blocking call: no CKF_DONT_BLOCK
    }

    [Fact]
    public void NonBlocking_SetsDontBlockFlag()
    {
        var fake = new SlotEventFake();
        using var library = new Pkcs11Library(fake);

        library.WaitForSlotEvent(nonBlocking: true);

        Assert.Equal((NativeCULong)CKF.CKF_DONT_BLOCK, fake.CapturedFlags);
    }

    [Fact]
    public void NonBlocking_NoEventPending_ReturnsFalseWithoutThrowing()
    {
        var fake = new SlotEventFake { Rv = CKR.CKR_NO_EVENT };
        using var library = new Pkcs11Library(fake);

        ulong? slotId = library.WaitForSlotEvent(nonBlocking: true);

        Assert.Null(slotId);
    }

    [Fact]
    public void ErrorCode_Throws()
    {
        var fake = new SlotEventFake { Rv = CKR.CKR_GENERAL_ERROR };
        using var library = new Pkcs11Library(fake);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(
            () => library.WaitForSlotEvent(nonBlocking: false));
        Assert.Equal(CKR.CKR_GENERAL_ERROR, ex.ReturnValue);
    }

    [Fact]
    public void AfterDispose_Throws()
    {
        var fake = new SlotEventFake();
        var library = new Pkcs11Library(fake);
        library.Dispose();

        Assert.Throws<ObjectDisposedException>(() => library.WaitForSlotEvent(nonBlocking: false));
    }
}
