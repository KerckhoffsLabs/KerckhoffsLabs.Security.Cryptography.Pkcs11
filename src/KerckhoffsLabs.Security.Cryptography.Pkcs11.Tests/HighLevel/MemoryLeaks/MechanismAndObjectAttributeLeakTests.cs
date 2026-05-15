using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.MemoryLeaks;

[Collection("MemoryLeaks")]
public sealed class MechanismAndObjectAttributeLeakTests : IDisposable
{
    private readonly bool _wasDebug;

    public MechanismAndObjectAttributeLeakTests()
    {
        _wasDebug = UnmanagedMemory.DebugModeEnabled;
        UnmanagedMemory.DebugModeEnabled = true;
        // Settle any pending finalizers from prior tests so they can't drift
        // OutstandingAllocationCount mid-test (UnmanagedMemory's tracker is
        // process-wide and now always populated regardless of the debug flag).
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
    }

    public void Dispose() => UnmanagedMemory.DebugModeEnabled = _wasDebug;

    [Fact]
    public void Mechanism_NoLeak_PlainMechanism()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < 20; i++)
        {
            using var m = new Mechanism(CKM.CKM_AES_KEY_GEN);
            _ = m.ToMarshalableStructure();
        }
        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }

    [Fact]
    public void Mechanism_NoLeak_WithIMechanismParams()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < 20; i++)
        {
            using var p = new CkmAesGcmParams(iv: new byte[12], aad: ReadOnlySpan<byte>.Empty, tagBits: 128);
            using var m = new Mechanism(CKM.CKM_AES_GCM, p);
            _ = m.ToMarshalableStructure();
        }
        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }

    [Fact]
    public void ObjectAttribute_NoLeak_BoolValue()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < 20; i++)
        {
            using var a = new ObjectAttribute(CKA.CKA_TOKEN, false);
        }
        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }

    [Fact]
    public void ObjectAttribute_NoLeak_ByteArrayValue()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < 20; i++)
        {
            using var a = new ObjectAttribute(CKA.CKA_VALUE, new byte[32]);
        }
        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }

    [Fact]
    public void ObjectAttribute_NoLeak_UlongValue()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < 20; i++)
        {
            using var a = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        }
        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }
}
