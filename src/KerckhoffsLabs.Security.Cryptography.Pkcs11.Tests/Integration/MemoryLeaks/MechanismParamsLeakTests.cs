using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.MemoryLeaks;

[Collection("MemoryLeaks")]
public sealed class MechanismParamsLeakTests : IDisposable
{
    private readonly bool _wasDebug;

    public MechanismParamsLeakTests()
    {
        _wasDebug = UnmanagedMemory.DebugModeEnabled;
        UnmanagedMemory.DebugModeEnabled = true;
        // Settle any pending finalizers from prior tests so they can't fire
        // between the per-test baseline snapshot and the final assertion and
        // drift OutstandingAllocationCount downward. UnmanagedMemory's tracking
        // is process-wide, so allocations from other tests are also in the
        // dictionary and decrement the count on finalization.
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
    }

    public void Dispose() => UnmanagedMemory.DebugModeEnabled = _wasDebug;

    /// <summary>
    /// Drives the full per-call cycle ten times — construct the descriptor, marshal it into a scope,
    /// absorb, release — and asserts that no unmanaged byte survives the operation. That is the same
    /// property the old constructor-oriented version asserted, pointed at whatever owns the memory now.
    /// </summary>
    /// <remarks>
    /// The mid-cycle "count rose" assertion is the load-bearing one. The descriptors no longer
    /// allocate anything in their constructors, so a test that only snapshots the counter and asserts
    /// it came back would read <c>baseline == baseline</c> and pass forever — including if marshalling
    /// stopped allocating, or if the scope were never given anything to free. Requiring the count to
    /// rise first is what keeps this measuring something.
    /// <para>
    /// The cycle goes through <see cref="Mechanism.Marshal"/> rather than
    /// <c>BuildMarshalable</c> alone, because that is what a session does, and because it allocates
    /// the <c>CK_MECHANISM</c> parameter block for every type — including the pointer-free ones like
    /// RSA-PSS and RC2, whose <c>BuildMarshalable</c> allocates nothing at all and so could not
    /// satisfy the rise assertion on its own.
    /// </para>
    /// </remarks>
    private static void AssertMarshalCycleLeaksNothing(CKM type, Func<MechanismParameters> create)
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;

        for (int i = 0; i < 10; i++)
        {
            MechanismParameters p = create();
            var mech = new Mechanism(type, p);

            // Pure managed descriptors: constructing either must not reach unmanaged memory.
            Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);

            using (var scope = new MechanismParameterScope())
            {
                CK_MECHANISM marshalled = mech.Marshal(scope, out object? mechParams);
                mech.AbsorbOutput(mechParams);

                Assert.NotEqual(IntPtr.Zero, marshalled.Parameter);
                Assert.True(
                    UnmanagedMemory.OutstandingAllocationCount > baseline,
                    "Marshalling allocated nothing, so this test cannot detect a leaked scope.");
            }

            // Every block the scope owned is back.
            Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
        }
    }

    [Fact]
    public void CkmAesGcmParams_NoLeak() =>
        AssertMarshalCycleLeaksNothing(CKM.CKM_AES_GCM, static () => new CkmAesGcmParams(
            iv: new byte[12],
            aad: new byte[16],
            tagBits: 128));

    [Fact]
    public void CkmRsaPkcsOaepParams_NoLeak() =>
        AssertMarshalCycleLeaksNothing(CKM.CKM_RSA_PKCS_OAEP, static () => new CkmRsaPkcsOaepParams(
            hashAlg: CKM.CKM_SHA256,
            mgf: CKG.CKG_MGF1_SHA256,
            sourceData: new byte[16]));

    [Fact]
    public void CkmRsaPkcsPssParams_NoLeak() =>
        AssertMarshalCycleLeaksNothing(CKM.CKM_RSA_PKCS_PSS, static () => new CkmRsaPkcsPssParams(
            hashAlg: CKM.CKM_SHA256,
            mgf: CKG.CKG_MGF1_SHA256,
            saltLength: 32));

    [Fact]
    public void CkmSalsa20ChaCha20Poly1305Params_NoLeak() =>
        AssertMarshalCycleLeaksNothing(CKM.CKM_CHACHA20_POLY1305, static () => new CkmSalsa20ChaCha20Poly1305Params(
            nonce: new byte[12],
            aad: new byte[16]));

    [Fact]
    public void CkmSp800108CounterKdfParams_NoLeak() =>
        AssertMarshalCycleLeaksNothing(CKM.CKM_SP800_108_COUNTER_KDF, static () => CkmSp800108KdfParams.CounterModeHmac(
            prfType: CKM.CKM_SHA256_HMAC,
            label: new byte[9],
            context: new byte[11]));

    // The empty label/context variant marshals two zero-length byte-array segments, which
    // MechanismParameterScope.Write maps to IntPtr.Zero rather than a block. The scope must still
    // come out even, and must not try to free the null pointers it never allocated.
    [Fact]
    public void CkmSp800108CounterKdfParams_EmptyLabelAndContext_NoLeak() =>
        AssertMarshalCycleLeaksNothing(CKM.CKM_SP800_108_COUNTER_KDF, static () => CkmSp800108KdfParams.CounterModeHmac(
            prfType: CKM.CKM_SHA256_HMAC,
            label: default,
            context: default));

    [Fact]
    public void CkmEcdh1DeriveParams_NoLeak() =>
        AssertMarshalCycleLeaksNothing(CKM.CKM_ECDH1_DERIVE, static () =>
        {
            // Realistic P-256 EC point shape (uncompressed 04 || X || Y).
            byte[] peerPublicPoint = new byte[65];
            peerPublicPoint[0] = 0x04;
            return new CkmEcdh1DeriveParams(
                kdf: CKD.CKD_SHA256_KDF,
                peerPublicPoint: peerPublicPoint,
                sharedData: new byte[16]);
        });

    /// <summary>
    /// The descriptors' own contribution to the cycle, isolated: constructing one of each must not
    /// touch unmanaged memory. This is what makes the mid-cycle rise attributable to the scope rather
    /// than to a constructor that quietly started allocating again.
    /// </summary>
    [Fact]
    public void ConstructingDescriptors_TouchesNoUnmanagedMemory()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;

        var gcm = new CkmAesGcmParams(new byte[12], new byte[16], 128);
        var oaep = new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, new byte[16]);
        var pss = new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32);
        var kdf = CkmSp800108KdfParams.CounterModeHmac(CKM.CKM_SHA256_HMAC, new byte[9], new byte[11]);
        var ecdh = new CkmEcdh1DeriveParams(CKD.CKD_SHA256_KDF, new byte[65], new byte[16]);

        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }
}
