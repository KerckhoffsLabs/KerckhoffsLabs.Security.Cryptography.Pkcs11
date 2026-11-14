using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// <see cref="Pkcs11Library.GetSlotByTokenLabel"/>: an exact (ordinal) match on the token label with the
/// space padding PKCS#11 puts on it removed, a typed token exception when no present token has the label,
/// and a refusal naming every matching slot when more than one does, rather than picking one (BL-079 c).
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11LibrarySlotByLabelTests
{
    // Slots and the label each one's token reports, padded to 32 characters by NativeTestStructs.FillPadded.
    private sealed class LabelledSlotsModule(params (ulong SlotId, string Label)[] tokens) : FakeModule
    {
        public int LoginCalls { get; private set; }

        protected override CKR C_GetSlotList(bool tokenPresent, NativeBuffer<NativeCULong> slotList, ref NativeCULong count)
        {
            if (slotList.IsNull)
            {
                count = (NativeCULong)(ulong)tokens.Length;
                return CKR.CKR_OK;
            }

            for (int i = 0; i < tokens.Length; i++)
                slotList.Span[i] = (NativeCULong)tokens[i].SlotId;
            count = (NativeCULong)(ulong)tokens.Length;
            return CKR.CKR_OK;
        }

        protected override CKR C_GetTokenInfo(NativeCULong slotId, ref CK_TOKEN_INFO info)
        {
            foreach ((ulong id, string label) in tokens)
            {
                if (id == (ulong)slotId)
                {
                    NativeTestStructs.FillPadded(info.Label, label);
                    return CKR.CKR_OK;
                }
            }

            return CKR.CKR_SLOT_ID_INVALID;
        }

        protected override CKR C_Login(NativeCULong session, NativeCULong userType, ReadOnlySpan<byte> pin)
        {
            LoginCalls++;
            return CKR.CKR_OK;
        }
    }

    [Fact]
    public void NoMatch_Throws()
    {
        using var fake = new LabelledSlotsModule((1, "alpha"), (2, "beta"));
        using Pkcs11Library library = fake.Load();

        var ex = Assert.Throws<Pkcs11TokenException>(() => library.GetSlotByTokenLabel("gamma"));

        Assert.Equal(CKR.CKR_TOKEN_NOT_PRESENT, ex.ReturnValue);
        Assert.Contains("gamma", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void LabelDiffersInCase_DoesNotMatch()
    {
        using var fake = new LabelledSlotsModule((1, "Alpha"));
        using Pkcs11Library library = fake.Load();

        Assert.Throws<Pkcs11TokenException>(() => library.GetSlotByTokenLabel("alpha"));
    }

    [Fact]
    public void TwoTokensSameLabel_ThrowsNamingBothSlots()
    {
        using var fake = new LabelledSlotsModule((3, "shared"), (8, "other"), (17, "shared"));
        using Pkcs11Library library = fake.Load();

        var ex = Assert.Throws<Pkcs11AmbiguousTokenException>(() => library.GetSlotByTokenLabel("shared"));

        Assert.Contains("3", ex.Message, StringComparison.Ordinal);
        Assert.Contains("17", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("8", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void PaddedLabel_Matches()
    {
        using var fake = new LabelledSlotsModule((1, "alpha"), (5, "beta"));
        using Pkcs11Library library = fake.Load();

        Pkcs11Slot slot = library.GetSlotByTokenLabel("beta");

        Assert.Equal(new SlotId(5), slot.SlotId);
        Assert.Equal(0, fake.LoginCalls); // finding a slot never logs in
    }

    [Fact]
    public void NullLabel_Throws()
    {
        using var fake = new LabelledSlotsModule((1, "alpha"));
        using Pkcs11Library library = fake.Load();

        Assert.Throws<ArgumentNullException>(() => library.GetSlotByTokenLabel(null!));
    }
}
