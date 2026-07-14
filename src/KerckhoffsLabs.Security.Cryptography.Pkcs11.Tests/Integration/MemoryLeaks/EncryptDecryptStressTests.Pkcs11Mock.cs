using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// These tests drive the gated legacy mechanisms/hashes on purpose (the AllowInsecure gate is the
// behaviour under test), so the compile-time warning is suppressed for this file only.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.MemoryLeaks;

/// <summary>
/// Omnibus 100-cycle stress test that exercises a realistic workload
/// (CreateObject + Encrypt + DestroyObject) against the Mock backend with
/// forced GC + WaitForPendingFinalizers before the final assertion. The
/// purpose is allocation discipline, not crypto correctness; mock-specific
/// <c>CreateObject</c> and <c>Encrypt</c> CKR codes are caught and swallowed.
/// A <c>DestroyObject</c> failure for a key that <c>CreateObject</c> did create
/// is NOT swallowed — that would leak a token-object handle the unmanaged-memory
/// baseline cannot see, so it must fail the test.
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

        // Track token-object handles independently of unmanaged-memory blocks: every key the
        // mock actually creates must be destroyed exactly once. A CreateObject success paired with
        // a DestroyObject failure would leak a handle that OutstandingAllocationCount never sees.
        int created = 0;
        int destroyed = 0;

        for (int i = 0; i < 100; i++)
        {
            var session = TestKeys.OpenLoggedInSession(_backend);
            // Raw AES-CBC is gated by default; opt in since this stress test only
            // cares about unmanaged-allocation discipline, not the choice of mechanism.
            session.AllowInsecure = true;
            try
            {
                // Build the Mechanism and attempt a realistic create+encrypt+destroy cycle.
                using var mech = new Mechanism(CKM.CKM_AES_CBC, iv);

                // The mock may reject C_CreateObject outright; if it does, nothing was created and
                // there is nothing to clean up for this cycle.
                ObjectHandle key;
                try
                {
                    key = TestKeys.CreateAes256Key(session, rawKey);
                }
                catch (Pkcs11Exception)
                {
                    continue;
                }

                created++;
                try
                {
                    // The mock backend may reject C_EncryptInit with a CKR_* code; that is fine —
                    // the assertion is about allocation discipline, not crypto output.
                    byte[] plaintext = new byte[16];
                    _ = session.Encrypt(mech, key, plaintext);
                }
                catch (Pkcs11Exception)
                {
                    // Mock-specific encrypt CKR codes are not the point.
                }
                finally
                {
                    // A key that was successfully created MUST be destroyed regardless of the
                    // encrypt outcome. Do NOT swallow a DestroyObject failure here — it would leave
                    // the token-object handle leaked, which is exactly what this test guards against.
                    session.DestroyObject(key);
                    destroyed++;
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
        // Every key the mock created was destroyed — no leaked token-object handles.
        Assert.Equal(created, destroyed);
    }
}
