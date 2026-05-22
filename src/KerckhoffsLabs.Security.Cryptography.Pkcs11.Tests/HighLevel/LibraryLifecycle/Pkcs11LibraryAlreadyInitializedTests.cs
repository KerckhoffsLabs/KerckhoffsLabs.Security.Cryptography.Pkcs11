using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.LibraryLifecycle;

/// <summary>
/// Regression: a second <see cref="Pkcs11Library"/> instance pointing at the
/// same path observes <c>CKR_CRYPTOKI_ALREADY_INITIALIZED</c> (the OS loader refcounts
/// the shared image, so the same global cryptoki state is reused). The second
/// instance's <c>Dispose</c> must not call <c>C_Finalize</c> — that would tear down
/// the first instance's library state.
/// </summary>
[Collection("Mock")]
public sealed class Pkcs11LibraryAlreadyInitializedTests(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void SecondInstance_DisposeLeavesFirstInstanceUsable()
    {
        // The collection fixture already holds an open library (instance A) against
        // _backend.LibraryPath. Open a second instance against the same path — pkcs11-mock
        // sees C_Initialize a second time and returns CKR_CRYPTOKI_ALREADY_INITIALIZED.
        Pkcs11Library b = new(_backend.LibraryPath);

        // Both instances must be usable while live — the second instance must not have
        // failed initialization.
        Assert.False(string.IsNullOrWhiteSpace(_backend.Library.GetInfo().ManufacturerId));
        Assert.False(string.IsNullOrWhiteSpace(b.GetInfo().ManufacturerId));

        // Dispose B. The fix means B did NOT drive C_Initialize → _weInitialized = false
        // → Dispose does NOT call C_Finalize. Without the fix, B's Dispose would call
        // C_Finalize and tear down the library state shared with A.
        b.Dispose();

        // A must still work post-B-dispose. If the bug regressed, this throws
        // Pkcs11Exception with CKR_CRYPTOKI_NOT_INITIALIZED.
        Assert.False(string.IsNullOrWhiteSpace(_backend.Library.GetInfo().ManufacturerId));
    }
}
