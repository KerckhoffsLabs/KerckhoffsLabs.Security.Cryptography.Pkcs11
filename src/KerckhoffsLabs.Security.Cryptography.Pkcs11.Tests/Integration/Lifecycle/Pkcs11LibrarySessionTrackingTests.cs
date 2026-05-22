using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Lifecycle;

/// <summary>
/// Regression: <see cref="Pkcs11Library.Dispose"/> must close every still-live
/// <c>Pkcs11SessionHandle</c> before <c>C_Finalize</c> and module unload. Otherwise a
/// stray SafeHandle finalizer would call <c>C_CloseSession</c> through a function table
/// whose backing module has been unmapped.
/// </summary>
/// <remarks>
/// These tests open a fresh <see cref="Pkcs11Library"/> rather than reusing the
/// collection fixture, because we deliberately dispose the library and observe its
/// internal session tracker.
/// </remarks>
[Collection("Mock")]
public sealed class Pkcs11LibrarySessionTrackingTests(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void OpeningSession_RegistersWithLibraryTracker()
    {
        Pkcs11Library library = new(_backend.LibraryPath);
        try
        {
            int before = library.LowLevelLibrary!.TrackedSessionCount;

            var slot = library.GetSlotList()[0];
            var session = slot.OpenSession();
            try
            {
                Assert.Equal(before + 1, library.LowLevelLibrary.TrackedSessionCount);
            }
            finally
            {
                session.Dispose();
            }
        }
        finally
        {
            library.Dispose();
        }
    }

    [Fact]
    public void DisposingSession_RemovesItFromLibraryTracker()
    {
        Pkcs11Library library = new(_backend.LibraryPath);
        try
        {
            int before = library.LowLevelLibrary!.TrackedSessionCount;
            var slot = library.GetSlotList()[0];

            var session = slot.OpenSession();
            Assert.Equal(before + 1, library.LowLevelLibrary.TrackedSessionCount);

            session.Dispose();
            Assert.Equal(before, library.LowLevelLibrary.TrackedSessionCount);
        }
        finally
        {
            library.Dispose();
        }
    }

    [Fact]
    public void DisposingLibrary_WithOpenSession_DoesNotThrow_AndClosesSession()
    {
        Pkcs11Library library = new(_backend.LibraryPath);
        var slot = library.GetSlotList()[0];
        var session = slot.OpenSession();

        // Capture the low-level wrapper before disposing the library — after dispose the
        // accessor returns null. The wrapper itself is kept alive by the session SafeHandle's
        // strong reference, so TrackedSessionCount is still readable.
        var lowLevel = library.LowLevelLibrary!;
        Assert.Equal(1, lowLevel.TrackedSessionCount);

        // Dispose the library WITHOUT first disposing the session. The fix must close
        // the session before C_Finalize, so no exception escapes.
        library.Dispose();

        // Tracker must have been drained by CloseAllTrackedSessions.
        Assert.Equal(0, lowLevel.TrackedSessionCount);

        // The session's SafeHandle should now be closed — its finalizer becomes a no-op,
        // which is the actual safety property (no C_CloseSession against an unloaded
        // function table).
        session.Dispose(); // idempotent — must not throw even though the library is gone
    }

    [Fact]
    public void DisposingLibrary_WithSessionAlreadyDisposed_NoOps()
    {
        Pkcs11Library library = new(_backend.LibraryPath);
        var slot = library.GetSlotList()[0];
        var session = slot.OpenSession();
        session.Dispose();

        var lowLevel = library.LowLevelLibrary!;
        Assert.Equal(0, lowLevel.TrackedSessionCount);

        // Library.Dispose with no live sessions must still succeed.
        library.Dispose();
        Assert.Equal(0, lowLevel.TrackedSessionCount);
    }
}
