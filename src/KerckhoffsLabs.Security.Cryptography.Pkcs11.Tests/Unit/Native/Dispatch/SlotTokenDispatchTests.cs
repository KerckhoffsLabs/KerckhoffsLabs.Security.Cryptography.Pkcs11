using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native.Dispatch;

/// <summary>
/// The slot and token wrappers, called through a module's function table: each reaches the module with
/// its slot and returns what the module writes, across the Windows struct packing, and the two lists
/// refuse a count larger than the room they gave or one no caller could allocate.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class SlotTokenDispatchTests
{
    private const ulong Slot = 2;
    private static readonly byte[] Label = [.. Enumerable.Repeat((byte)' ', 32)];

    private static readonly Dictionary<string, DispatchCase> Cases = new DispatchCase[]
    {
        new(nameof(LowLevelPkcs11Library.C_GetSlotList), l =>
        {
            NativeCULong[] slots = new NativeCULong[4];
            CKR rv = l.C_GetSlotList(tokenPresent: true, slots, out NativeCULong count);
            return rv == CKR.CKR_OK && ((ulong)count != 1 || (ulong)slots[0] != Slot) ? CKR.CKR_GENERAL_ERROR : rv;
        }),
        new(nameof(LowLevelPkcs11Library.C_GetSlotInfo), l =>
        {
            CK_SLOT_INFO info = default;
            CKR rv = l.C_GetSlotInfo((NativeCULong)Slot, ref info);
            return rv == CKR.CKR_OK && ((ulong)info.Flags != 7 || info.FirmwareVersion.Major != 3) ? CKR.CKR_GENERAL_ERROR : rv;
        }),
        new(nameof(LowLevelPkcs11Library.C_GetTokenInfo), l =>
        {
            CK_TOKEN_INFO info = default;
            CKR rv = l.C_GetTokenInfo((NativeCULong)Slot, ref info);
            return rv == CKR.CKR_OK && (ulong)info.Flags != 9 ? CKR.CKR_GENERAL_ERROR : rv;
        }),
        new(nameof(LowLevelPkcs11Library.C_GetMechanismList), l =>
        {
            CKM[] mechanisms = new CKM[4];
            CKR rv = l.C_GetMechanismList((NativeCULong)Slot, mechanisms, out NativeCULong count);
            return rv == CKR.CKR_OK && ((ulong)count != 2 || mechanisms[1] != CKM.CKM_AES_GCM) ? CKR.CKR_GENERAL_ERROR : rv;
        }),
        new(nameof(LowLevelPkcs11Library.C_GetMechanismInfo), l =>
        {
            CK_MECHANISM_INFO info = default;
            CKR rv = l.C_GetMechanismInfo((NativeCULong)Slot, CKM.CKM_AES_GCM, ref info);
            return rv == CKR.CKR_OK && (ulong)info.MaxKeySize != 256 ? CKR.CKR_GENERAL_ERROR : rv;
        }),
        new(nameof(LowLevelPkcs11Library.C_InitToken), l => l.C_InitToken((NativeCULong)Slot, "1234"u8, Label)),
        new(nameof(LowLevelPkcs11Library.C_WaitForSlotEvent), l =>
        {
            NativeCULong slot = default;
            CKR rv = l.C_WaitForSlotEvent((NativeCULong)(ulong)CKF.CKF_DONT_BLOCK, ref slot, IntPtr.Zero);
            return rv == CKR.CKR_OK && (ulong)slot != Slot ? CKR.CKR_GENERAL_ERROR : rv;
        }),
    }.ToDictionary(c => c.Function, StringComparer.Ordinal);

    public static TheoryData<string> Functions => [.. Cases.Keys];

    private static readonly HashSet<string> TakesSlot =
    [
        nameof(LowLevelPkcs11Library.C_GetSlotInfo), nameof(LowLevelPkcs11Library.C_GetTokenInfo), nameof(LowLevelPkcs11Library.C_GetMechanismList),
        nameof(LowLevelPkcs11Library.C_GetMechanismInfo), nameof(LowLevelPkcs11Library.C_InitToken),
    ];

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_ReachesTheModule_AndReturnsWhatItWrites(string function)
    {
        using var module = new SlotModule();

        Assert.Equal(CKR.CKR_OK, DispatchSmoke.ReachesTheModule(module, Cases[function]));

        if (TakesSlot.Contains(function))
            Assert.Equal(Slot, module.LastSlot);
    }

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_OfAFunctionTheModuleLacks_ReturnsNotSupported(string function)
        => DispatchSmoke.ReportsAMissingFunctionUnsupported(Cases[function]);

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_AfterDispose_Throws_WithoutReachingTheModule(string function)
    {
        using var module = new SlotModule();
        DispatchSmoke.RefusesACallAfterDispose(module, Cases[function]);
    }

    [Fact]
    public void GetSlotList_ReportingMoreSlotsThanTheBufferHolds_IsRefused()
    {
        using var module = new SlotModule { OverReports = true };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        Assert.Throws<Pkcs11UnclassifiedException>(() => lowLevel.C_GetSlotList(true, new NativeCULong[4], out _));
    }

    [Fact]
    public void GetMechanismList_ReportingMoreMechanismsThanTheBufferHolds_IsRefused()
    {
        using var module = new SlotModule { OverReports = true };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        Assert.Throws<Pkcs11UnclassifiedException>(() => lowLevel.C_GetMechanismList((NativeCULong)Slot, new CKM[4], out _));
    }

    [Fact]
    public void CountQueries_ReportingUnavailableInformation_AreRefused()
    {
        using var module = new SlotModule { QueryReports = NativeCULong.MaxValue };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        Assert.Throws<Pkcs11UnclassifiedException>(() => lowLevel.C_GetSlotList(true, [], out _));
        Assert.Throws<Pkcs11UnclassifiedException>(() => lowLevel.C_GetMechanismList((NativeCULong)Slot, [], out _));
    }

    private sealed class SlotModule : FakeModule
    {
        public bool OverReports { get; init; }
        public NativeCULong? QueryReports { get; init; }

        public ulong LastSlot { get; private set; }

        protected override CKR C_GetSlotList(bool tokenPresent, NativeBuffer<NativeCULong> slotList, ref NativeCULong count)
            => List(slotList, ref count, [(NativeCULong)Slot]);

        protected override CKR C_GetSlotInfo(NativeCULong slotId, ref CK_SLOT_INFO info)
        {
            info.Flags = (NativeCULong)7;
            info.FirmwareVersion = new CK_VERSION { Major = 3, Minor = 2 };
            return Received(slotId);
        }

        protected override CKR C_GetTokenInfo(NativeCULong slotId, ref CK_TOKEN_INFO info)
        {
            info.Flags = (NativeCULong)9;
            return Received(slotId);
        }

        protected override CKR C_GetMechanismList(NativeCULong slotId, NativeBuffer<NativeCULong> mechanismList, ref NativeCULong count)
        {
            Received(slotId);
            return List(mechanismList, ref count, [(NativeCULong)(ulong)CKM.CKM_AES_KEY_GEN, (NativeCULong)(ulong)CKM.CKM_AES_GCM]);
        }

        protected override CKR C_GetMechanismInfo(NativeCULong slotId, NativeCULong type, ref CK_MECHANISM_INFO info)
        {
            info.MaxKeySize = (NativeCULong)256;
            return Received(slotId);
        }

        protected override CKR C_InitToken(NativeCULong slotId, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> label) => Received(slotId);

        protected override CKR C_WaitForSlotEvent(NativeCULong flags, ref NativeCULong slot)
        {
            slot = (NativeCULong)Slot;
            return CKR.CKR_OK;
        }

        private CKR Received(NativeCULong slotId)
        {
            LastSlot = (ulong)slotId;
            return CKR.CKR_OK;
        }

        private CKR List(NativeBuffer<NativeCULong> list, ref NativeCULong count, NativeCULong[] items)
        {
            if (list.IsNull)
            {
                count = QueryReports ?? (NativeCULong)(ulong)items.Length;
                return CKR.CKR_OK;
            }
            items.CopyTo(list.Span);
            count = (NativeCULong)(ulong)(OverReports ? list.Span.Length + 1 : items.Length);
            return CKR.CKR_OK;
        }
    }
}
