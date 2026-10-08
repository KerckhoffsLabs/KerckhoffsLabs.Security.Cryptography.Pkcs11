using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// Hermetic coverage for Pkcs11Library.GetSlotList's two edge cases the pkcs11-mock integration
/// suite never exercises: zero slots, and a token whose slot count is lower on the second
/// (fill) C_GetSlotList call than the first (probe) call — the PKCS#11 spec allows this (a slot
/// could disappear between calls), and the caller must resize down rather than read stale entries.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class GetSlotListTests
{
    private sealed class SlotListFake : FakeModule
    {
        public NativeCULong ProbeCount = (NativeCULong)0;
        public NativeCULong[] FillSlots = [];
        public NativeCULong FillCount = (NativeCULong)0;

        protected override CKR C_GetSlotList(bool tokenPresent, NativeBuffer<NativeCULong> slotList, ref NativeCULong count)
        {
            if (slotList.IsNull)
            {
                count = ProbeCount;
                return CKR.CKR_OK;
            }

            FillSlots.AsSpan().CopyTo(slotList.Span);
            count = FillCount;
            return CKR.CKR_OK;
        }
    }

    [Fact]
    public void ZeroSlots_ReturnsEmptyWithoutASecondCall()
    {
        using var fake = new SlotListFake { ProbeCount = (NativeCULong)0 };
        using var library = fake.Load();

        Assert.Empty(library.GetSlotList());
    }

    [Fact]
    public void SecondCallReportsFewerSlots_ResizesToMatch()
    {
        using var fake = new SlotListFake
        {
            ProbeCount = (NativeCULong)2,
            FillSlots = [(NativeCULong)7],
            FillCount = (NativeCULong)1,
        };
        using var library = fake.Load();

        var slots = library.GetSlotList();

        Assert.Single(slots);
    }

    [Fact]
    public void SecondCallReportsMoreSlotsThanTheBuffer_IsRefused_NotPaddedWithSlotZero()
    {
        using var fake = new SlotListFake
        {
            ProbeCount = (NativeCULong)1,
            FillSlots = [(NativeCULong)7],
            FillCount = (NativeCULong)2,
        };
        using var library = fake.Load();

        // Padding used to add slot 0, a slot the module never listed.
        Assert.Throws<Pkcs11UnclassifiedException>(() => library.GetSlotList());
    }

    [Fact]
    public void ProbeReportsUnavailableInformation_IsRefused()
    {
        using var fake = new SlotListFake { ProbeCount = NativeCULong.MaxValue };
        using var library = fake.Load();

        Assert.Throws<Pkcs11UnclassifiedException>(() => library.GetSlotList());
    }
}
