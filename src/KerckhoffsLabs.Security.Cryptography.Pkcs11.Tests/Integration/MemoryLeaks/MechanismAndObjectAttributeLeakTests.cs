using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.MemoryLeaks;

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

    // A mechanism with no parameter marshals to a null Parameter and allocates nothing, so there is
    // no rise to assert here — the property is only that the cycle stays flat. The
    // Assert.Equal(IntPtr.Zero) is what stops this from being vacuous: it pins the reason the count
    // did not move, rather than letting a silently-stopped allocation look like the same result.
    [Fact]
    public void Mechanism_NoLeak_PlainMechanism()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < 20; i++)
        {
            using var m = new Mechanism(CKM.CKM_AES_KEY_GEN);
            using (var scope = new MechanismParameterScope())
            {
                CK_MECHANISM marshalled = m.Marshal(scope, out object? mechParams);
                Assert.Equal(IntPtr.Zero, marshalled.Parameter);
                Assert.Null(mechParams);
            }
            Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
        }
        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }

    [Fact]
    public void Mechanism_NoLeak_WithMechanismParams()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < 20; i++)
        {
            using var p = new CkmAesGcmParams(iv: new byte[12], aad: [], tagBits: 128);
            using var m = new Mechanism(CKM.CKM_AES_GCM, p);

            // Neither object owns unmanaged memory of its own any more.
            Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);

            using (var scope = new MechanismParameterScope())
            {
                CK_MECHANISM marshalled = m.Marshal(scope, out object? mechParams);
                // CkmAesGcmParams has no output fields, so this absorb is a no-op; it is here because
                // the cycle under test is the session's, and the session always absorbs.
                m.AbsorbOutput(mechParams);

                Assert.NotEqual(IntPtr.Zero, marshalled.Parameter);
                Assert.True(
                    UnmanagedMemory.OutstandingAllocationCount > baseline,
                    "Marshalling allocated nothing, so this test cannot detect a leaked scope.");
            }

            Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
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
