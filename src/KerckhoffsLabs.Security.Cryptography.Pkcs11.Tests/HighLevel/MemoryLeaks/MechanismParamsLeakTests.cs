using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.MemoryLeaks;

[Collection("MemoryLeaks")]
public sealed class MechanismParamsLeakTests : IDisposable
{
    private readonly bool _wasDebug;

    public MechanismParamsLeakTests()
    {
        _wasDebug = UnmanagedMemory.DebugModeEnabled;
        UnmanagedMemory.DebugModeEnabled = true;
    }

    public void Dispose() => UnmanagedMemory.DebugModeEnabled = _wasDebug;

    [Fact]
    public void CkmAesGcmParams_NoLeak()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < 10; i++)
        {
            using var p = new CkmAesGcmParams(
                iv: new byte[12],
                aad: new byte[16],
                tagBits: 128);
            _ = p.ToMarshalableStructure();
        }
        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }

    [Fact]
    public void CkmRsaPkcsOaepParams_NoLeak()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < 10; i++)
        {
            using var p = new CkmRsaPkcsOaepParams(
                hashAlg: CKM.CKM_SHA256,
                mgf: CKG.CKG_MGF1_SHA256,
                sourceData: new byte[16]);
            _ = p.ToMarshalableStructure();
        }
        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }

    [Fact]
    public void CkmRsaPkcsPssParams_NoLeak()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < 10; i++)
        {
            using var p = new CkmRsaPkcsPssParams(
                hashAlg: CKM.CKM_SHA256,
                mgf: CKG.CKG_MGF1_SHA256,
                saltLength: 32);
            _ = p.ToMarshalableStructure();
        }
        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }

    [Fact]
    public void CkmSalsa20ChaCha20Poly1305Params_NoLeak()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < 10; i++)
        {
            using var p = new CkmSalsa20ChaCha20Poly1305Params(
                nonce: new byte[12],
                aad: new byte[16]);
            _ = p.ToMarshalableStructure();
        }
        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }

    [Fact]
    public void CkmEcdh1DeriveParams_NoLeak()
    {
        int baseline = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < 10; i++)
        {
            // Realistic P-256 EC point shape (uncompressed 04 || X || Y).
            byte[] peerPublicPoint = new byte[65];
            peerPublicPoint[0] = 0x04;
            using var p = new CkmEcdh1DeriveParams(
                kdf: CKD.CKD_SHA256_KDF,
                peerPublicPoint: peerPublicPoint,
                sharedData: new byte[16]);
            _ = p.ToMarshalableStructure();
        }
        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }
}
