using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// Hermetic coverage for Pkcs11Library.WaitForSlotEvent — untouched by every other suite, since
/// nothing else in this project's test matrix generates a real slot event. Pins, for the blocking
/// WaitForSlotEvent and the polling TryGetSlotEvent, the CKF_DONT_BLOCK flag encoding, the event-occurred
/// path, what CKR_NO_EVENT means to each, error propagation, and the disposed guard.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class WaitForSlotEventTests
{
    private sealed class SlotEventFake : FakeModule
    {
        public NativeCULong CapturedFlags;
        public CKR Rv = CKR.CKR_OK;
        public ulong SlotIdToReport = 3;

        protected override CKR C_GetSlotList(bool tokenPresent, NativeBuffer<NativeCULong> slotList, ref NativeCULong count)
        {
            count = (NativeCULong)2;
            if (slotList.IsNull) return CKR.CKR_OK;
            if (slotList.Span.Length < 2) return CKR.CKR_BUFFER_TOO_SMALL;
            slotList.Span[0] = (NativeCULong)3UL;
            slotList.Span[1] = (NativeCULong)5UL;
            return CKR.CKR_OK;
        }

        protected override CKR C_WaitForSlotEvent(NativeCULong flags, ref NativeCULong slot)
        {
            CapturedFlags = flags;
            if (Rv == CKR.CKR_OK)
                slot = (NativeCULong)SlotIdToReport;
            return Rv;
        }
    }

    [Fact]
    public void Wait_EventOccurred_ReturnsSlot()
    {
        using var fake = new SlotEventFake { Rv = CKR.CKR_OK, SlotIdToReport = 5 };
        using var library = fake.Load();

        Pkcs11Slot slot = library.WaitForSlotEvent(TestContext.Current.CancellationToken);

        Assert.Equal(new SlotId(5), slot.SlotId);
        Assert.Equal((NativeCULong)0, fake.CapturedFlags); // blocking call: no CKF_DONT_BLOCK
    }

    [Fact]
    public void Wait_NoEventFromBlockingCall_Throws()
    {
        // A blocking call has no "nothing happened" result: a module returning CKR_NO_EVENT is an error.
        using var fake = new SlotEventFake { Rv = CKR.CKR_NO_EVENT };
        using var library = fake.Load();

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => library.WaitForSlotEvent(TestContext.Current.CancellationToken));
        Assert.Equal(CKR.CKR_NO_EVENT, ex.ReturnValue);
    }

    [Fact]
    public void Wait_ErrorCode_Throws()
    {
        using var fake = new SlotEventFake { Rv = CKR.CKR_GENERAL_ERROR };
        using var library = fake.Load();

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => library.WaitForSlotEvent(TestContext.Current.CancellationToken));
        Assert.Equal(CKR.CKR_GENERAL_ERROR, ex.ReturnValue);
    }

    [Fact]
    public void Wait_AfterDispose_Throws()
    {
        using var fake = new SlotEventFake();
        var library = fake.Load();
        library.Dispose();

        Assert.Throws<ObjectDisposedException>(() => library.WaitForSlotEvent(TestContext.Current.CancellationToken));
    }

    [Fact]
    public void TryGet_EventPending_ReturnsSlotAndSetsDontBlock()
    {
        using var fake = new SlotEventFake { Rv = CKR.CKR_OK, SlotIdToReport = 7 };
        using var library = fake.Load();

        Assert.True(library.TryGetSlotEvent(out Pkcs11Slot? slot));

        Assert.Equal(new SlotId(7), slot.SlotId);
        Assert.Equal((NativeCULong)CKF.CKF_DONT_BLOCK, fake.CapturedFlags);
    }

    [Fact]
    public void TryGet_NoEventPending_ReturnsFalseWithoutThrowing()
    {
        using var fake = new SlotEventFake { Rv = CKR.CKR_NO_EVENT };
        using var library = fake.Load();

        Assert.False(library.TryGetSlotEvent(out Pkcs11Slot? slot));
        Assert.Null(slot);
    }

    [Fact]
    public void TryGet_ErrorCode_Throws()
    {
        using var fake = new SlotEventFake { Rv = CKR.CKR_FUNCTION_NOT_SUPPORTED };
        using var library = fake.Load();

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => library.TryGetSlotEvent(out _));
        Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
    }

    [Fact]
    public void TryGet_AfterDispose_Throws()
    {
        using var fake = new SlotEventFake();
        var library = fake.Load();
        library.Dispose();

        Assert.Throws<ObjectDisposedException>(() => library.TryGetSlotEvent(out _));
    }

    // An event's slot must match the one GetSlotList reports for the same id, so callers can look it up
    // in a list or key a dictionary on it.
    [Fact]
    public void EventSlot_EqualsTheListedSlotWithTheSameId()
    {
        using var fake = new SlotEventFake { Rv = CKR.CKR_OK, SlotIdToReport = 5 };
        using var library = fake.Load();
        IReadOnlyList<Pkcs11Slot> listed = library.GetSlotList(tokenPresent: false);

        Pkcs11Slot slot = library.WaitForSlotEvent(TestContext.Current.CancellationToken);

        Assert.Contains(slot, listed);
        Assert.Equal(listed[1], slot);
        Assert.Equal(listed[1].GetHashCode(), slot.GetHashCode());
        Assert.NotEqual(listed[0], slot);
    }

    // A slot belongs to the library that produced it (it calls through that library, and stops working
    // when that library is disposed), so the same id from another library is another slot.
    [Fact]
    public void Slots_FromDifferentLibraries_AreNotEqual()
    {
        using var fake = new SlotEventFake { SlotIdToReport = 3 };
        using var a = fake.Load();
        using var b = fake.Load();

        Assert.NotEqual(a.WaitForSlotEvent(TestContext.Current.CancellationToken), b.WaitForSlotEvent(TestContext.Current.CancellationToken));
    }
}
