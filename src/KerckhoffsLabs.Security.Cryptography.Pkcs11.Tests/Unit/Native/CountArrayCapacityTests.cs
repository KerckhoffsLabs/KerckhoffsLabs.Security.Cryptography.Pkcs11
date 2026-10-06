using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// The capacity a module is told for a count array (<c>*pulCount</c> for <c>C_GetSlotList</c>,
/// <c>ulMaxObjectCount</c> for <c>C_FindObjects</c>) is the length of the buffer it writes into, taken
/// from the span rather than passed alongside it, so the two cannot disagree.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class CountArrayCapacityTests
{
    [Fact]
    public void GetSlotList_TellsTheModuleTheBuffersLength()
    {
        using var module = new CapacityModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        Span<NativeCULong> slots = stackalloc NativeCULong[3];

        CKR rv = lowLevel.C_GetSlotList(tokenPresent: true, slots, out NativeCULong count);

        Assert.Equal(CKR.CKR_OK, rv);
        Assert.Equal(3UL, module.SlotCapacityOnEntry);
        Assert.False(module.SlotListWasNull);
        Assert.Equal(1UL, (ulong)count);
        Assert.Equal(9UL, (ulong)slots[0]);
    }

    [Fact]
    public void GetSlotList_EmptyBuffer_IsALengthQuery()
    {
        using var module = new CapacityModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        CKR rv = lowLevel.C_GetSlotList(tokenPresent: true, [], out NativeCULong count);

        Assert.Equal(CKR.CKR_OK, rv);
        Assert.True(module.SlotListWasNull);
        Assert.Equal(0UL, module.SlotCapacityOnEntry);
        Assert.Equal(1UL, (ulong)count);
    }

    [Fact]
    public void FindObjects_MaxObjectCountIsTheBuffersLength()
    {
        using var module = new CapacityModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        Span<NativeCULong> objects = stackalloc NativeCULong[4];

        CKR rv = lowLevel.C_FindObjects(module.OpenSession(), objects, out NativeCULong count);

        Assert.Equal(CKR.CKR_OK, rv);
        Assert.Equal(4, module.FindCapacity);
        Assert.Equal(2UL, (ulong)count);
    }

    private sealed class CapacityModule : FakeModule
    {
        public ulong SlotCapacityOnEntry { get; private set; }
        public bool SlotListWasNull { get; private set; }
        public int FindCapacity { get; private set; }

        public NativeCULong OpenSession() => NewSessionHandle();

        protected override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;

        protected override CKR C_GetSlotList(bool tokenPresent, NativeBuffer<NativeCULong> slotList, ref NativeCULong count)
        {
            SlotCapacityOnEntry = (ulong)count;
            SlotListWasNull = slotList.IsNull;
            if (!slotList.IsNull)
                slotList.Span[0] = (NativeCULong)9UL;
            count = (NativeCULong)1UL;
            return CKR.CKR_OK;
        }

        protected override CKR C_FindObjects(NativeCULong session, Span<NativeCULong> objects, ref NativeCULong count)
        {
            FindCapacity = objects.Length;
            count = (NativeCULong)2UL;
            return CKR.CKR_OK;
        }
    }
}
