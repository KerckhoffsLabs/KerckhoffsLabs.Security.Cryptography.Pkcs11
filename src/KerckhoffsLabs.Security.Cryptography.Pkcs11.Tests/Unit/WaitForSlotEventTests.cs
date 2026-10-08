using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// Hermetic coverage for Pkcs11Library.WaitForSlotEvent — untouched by every other suite, since
/// nothing else in this project's test matrix generates a real slot event. Pins the
/// CKF_DONT_BLOCK flag encoding, the CKR_NO_EVENT non-blocking no-op, the event-occurred path,
/// error propagation, and the disposed guard.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class WaitForSlotEventTests
{
    private sealed class SlotEventFake : FakeModule
    {
        public NativeCULong CapturedFlags;
        public CKR Rv = CKR.CKR_OK;
        public ulong SlotIdToReport = 3;

        protected override CKR C_WaitForSlotEvent(NativeCULong flags, ref NativeCULong slot)
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
        using var fake = new SlotEventFake { Rv = CKR.CKR_OK, SlotIdToReport = 5 };
        using var library = fake.Load();

        ulong? slotId = library.WaitForSlotEvent(nonBlocking: false);

        Assert.Equal(5UL, slotId);
        Assert.Equal((NativeCULong)0, fake.CapturedFlags); // blocking call: no CKF_DONT_BLOCK
    }

    [Fact]
    public void NonBlocking_SetsDontBlockFlag()
    {
        using var fake = new SlotEventFake();
        using var library = fake.Load();

        library.WaitForSlotEvent(nonBlocking: true);

        Assert.Equal((NativeCULong)CKF.CKF_DONT_BLOCK, fake.CapturedFlags);
    }

    [Fact]
    public void NonBlocking_NoEventPending_ReturnsFalseWithoutThrowing()
    {
        using var fake = new SlotEventFake { Rv = CKR.CKR_NO_EVENT };
        using var library = fake.Load();

        ulong? slotId = library.WaitForSlotEvent(nonBlocking: true);

        Assert.Null(slotId);
    }

    [Fact]
    public void ErrorCode_Throws()
    {
        using var fake = new SlotEventFake { Rv = CKR.CKR_GENERAL_ERROR };
        using var library = fake.Load();

        var ex = Assert.ThrowsAny<Pkcs11Exception>(
            () => library.WaitForSlotEvent(nonBlocking: false));
        Assert.Equal(CKR.CKR_GENERAL_ERROR, ex.ReturnValue);
    }

    [Fact]
    public void AfterDispose_Throws()
    {
        using var fake = new SlotEventFake();
        var library = fake.Load();
        library.Dispose();

        Assert.Throws<ObjectDisposedException>(() => library.WaitForSlotEvent(nonBlocking: false));
    }
}
