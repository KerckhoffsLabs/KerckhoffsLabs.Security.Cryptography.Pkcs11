using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.MemoryLeaks;

/// <summary>
/// Omnibus 100-cycle stress test that exercises a realistic workload
/// (CreateObject + Encrypt + DestroyObject) against the Mock backend with
/// forced GC + WaitForPendingFinalizers before the final assertion. The
/// purpose is allocation discipline, not crypto correctness; mock-specific
/// CKR codes are caught and swallowed.
/// </summary>
[Collection("MemoryLeaks")]
public sealed class EncryptDecryptStressTests : IDisposable
{
    // Instantiate the fixture directly — the MemoryLeaks collection does not
    // declare MockBackendFixture as an ICollectionFixture, so constructor
    // injection is not available. We own the lifetime here.
    private readonly MockBackendFixture _backend;
    private readonly bool _wasDebug;

    public EncryptDecryptStressTests()
    {
        _backend = new MockBackendFixture();
        _wasDebug = UnmanagedMemory.DebugModeEnabled;
        UnmanagedMemory.DebugModeEnabled = true;
    }

    public void Dispose()
    {
        UnmanagedMemory.DebugModeEnabled = _wasDebug;
        _backend.Dispose();
    }

    [Fact]
    public void EncryptDecrypt_100Cycles_NoLeak()
    {
        // Settle prior finalizers before baselining.
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        int baseline = UnmanagedMemory.OutstandingAllocationCount;

        // A fresh 32-byte AES key value used for each CreateObject call.
        byte[] rawKey = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(rawKey);

        // AES-CBC requires a 16-byte IV; use a fixed all-zeros IV (fine for stress testing).
        byte[] iv = new byte[16];

        for (int i = 0; i < 100; i++)
        {
            var session = TestKeys.OpenLoggedInSession(_backend);
            // Raw AES-CBC is gated by default (BL-018); opt in since this stress test only
            // cares about unmanaged-allocation discipline, not the choice of mechanism.
            session.AllowInsecure = true;
            try
            {
                // Build the Mechanism and attempt a realistic create+encrypt+destroy cycle.
                // The mock backend may reject C_EncryptInit with a CKR_* code; that is fine —
                // the assertion is about unmanaged-allocation discipline, not crypto output.
                using var mech = new Mechanism(CKM.CKM_AES_CBC, iv);
                try
                {
                    var key = TestKeys.CreateAes256Key(session, rawKey);
                    try
                    {
                        byte[] plaintext = new byte[16];
                        _ = session.Encrypt(mech, key, plaintext);
                    }
                    catch (Pkcs11Exception)
                    {
                        // Mock-specific CKR codes are not the point.
                    }
                    finally
                    {
                        session.DestroyObject(key);
                    }
                }
                catch (Pkcs11Exception)
                {
                    // CreateObject can also be rejected by the mock; clean up gracefully.
                }
            }
            finally
            {
                session.Logout();
                session.CloseSession();
            }
        }

        // Force a full GC cycle to flush any deferred finalizers — anything still
        // outstanding after this is a real leak.
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        Assert.Equal(baseline, UnmanagedMemory.OutstandingAllocationCount);
    }
}
