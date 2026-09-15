using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// Hermetic coverage for Pkcs11Library.GetSlotList's two edge cases the pkcs11-mock integration
/// suite never exercises: zero slots, and a token whose slot count is lower on the second
/// (fill) C_GetSlotList call than the first (probe) call — the PKCS#11 spec allows this (a slot
/// could disappear between calls), and the caller must resize down rather than read stale entries.
/// </summary>
public sealed class GetSlotListTests
{
    private sealed class SlotListFake : NotSupportedPkcs11Library
    {
        public NativeCULong ProbeCount = (NativeCULong)0;
        public NativeCULong[] FillSlots = [];
        public NativeCULong FillCount = (NativeCULong)0;

        public override CKR C_Initialize(CK_C_INITIALIZE_ARGS? initArgs) => CKR.CKR_OK;
        public override CKR C_Finalize(IntPtr reserved) => CKR.CKR_OK;

        public override CKR C_GetSlotList(bool tokenPresent, NativeCULong[]? slotList, ref NativeCULong count)
        {
            if (slotList is null)
            {
                count = ProbeCount;
                return CKR.CKR_OK;
            }

            FillSlots.AsSpan().CopyTo(slotList);
            count = FillCount;
            return CKR.CKR_OK;
        }
    }

    [Fact]
    public void ZeroSlots_ReturnsEmptyWithoutASecondCall()
    {
        var fake = new SlotListFake { ProbeCount = (NativeCULong)0 };
        using var library = new Pkcs11Library(fake);

        Assert.Empty(library.GetSlotList());
    }

    [Fact]
    public void SecondCallReportsFewerSlots_ResizesToMatch()
    {
        var fake = new SlotListFake
        {
            ProbeCount = (NativeCULong)2,
            FillSlots = [(NativeCULong)7],
            FillCount = (NativeCULong)1,
        };
        using var library = new Pkcs11Library(fake);

        var slots = library.GetSlotList();

        Assert.Single(slots);
    }
}
