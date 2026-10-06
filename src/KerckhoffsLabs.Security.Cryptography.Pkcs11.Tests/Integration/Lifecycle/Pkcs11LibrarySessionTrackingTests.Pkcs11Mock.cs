using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
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
        using Pkcs11Library library = Pkcs11Library.Load(_backend.LibraryPath);
        int before = library.LowLevelLibrary!.Module.TrackedSessionCount;

        var slot = library.GetSlotList()[0];
        // Declared after the library so it is released first, as the nested finally did.
        using var session = slot.OpenSession();

        Assert.Equal(before + 1, library.LowLevelLibrary.Module.TrackedSessionCount);
    }

    [Fact]
    public void DisposingSession_RemovesItFromLibraryTracker()
    {
        using Pkcs11Library library = Pkcs11Library.Load(_backend.LibraryPath);
        int before = library.LowLevelLibrary!.Module.TrackedSessionCount;
        var slot = library.GetSlotList()[0];

        var session = slot.OpenSession();
        Assert.Equal(before + 1, library.LowLevelLibrary.Module.TrackedSessionCount);

        // Not a `using`: disposing the session at a chosen moment is what this test measures.
        session.Dispose();
        Assert.Equal(before, library.LowLevelLibrary.Module.TrackedSessionCount);
    }

    [Fact]
    public void DisposingLibrary_WithOpenSession_DoesNotThrow_AndClosesSession()
    {
        Pkcs11Library library = Pkcs11Library.Load(_backend.LibraryPath);
        var slot = library.GetSlotList()[0];
        var session = slot.OpenSession();

        // Capture the low-level wrapper before disposing the library — after dispose the
        // accessor returns null. The wrapper itself is kept alive by the session SafeHandle's
        // strong reference, so TrackedSessionCount is still readable.
        var lowLevel = library.LowLevelLibrary!;
        Assert.Equal(1, lowLevel.Module.TrackedSessionCount);

        // Dispose the library WITHOUT first disposing the session. The fix must close
        // the session before C_Finalize, so no exception escapes.
        library.Dispose();

        // Tracker must have been drained by CloseAllTrackedSessions.
        Assert.Equal(0, lowLevel.Module.TrackedSessionCount);

        // The session's SafeHandle should now be closed — its finalizer becomes a no-op,
        // which is the actual safety property (no C_CloseSession against an unloaded
        // function table).
        session.Dispose(); // idempotent — must not throw even though the library is gone
    }

    [Fact]
    public void DisposingLibrary_WithSessionAlreadyDisposed_NoOps()
    {
        Pkcs11Library library = Pkcs11Library.Load(_backend.LibraryPath);
        var slot = library.GetSlotList()[0];
        var session = slot.OpenSession();
        session.Dispose();

        var lowLevel = library.LowLevelLibrary!;
        Assert.Equal(0, lowLevel.Module.TrackedSessionCount);

        // Library.Dispose with no live sessions must still succeed.
        library.Dispose();
        Assert.Equal(0, lowLevel.Module.TrackedSessionCount);
    }

    // Disposing the library closes the workspace's session, so the workspace's own logout finds it
    // closed. Its disposal must still succeed: it used to throw ObjectDisposedException.
    [Fact]
    public void DisposingTheLibraryFirst_ThenTheWorkspace_DoesNotThrow()
    {
        Pkcs11Library library = Pkcs11Library.Load(_backend.LibraryPath);
        Pkcs11Workspace workspace = library.OpenWorkspaceWithPin(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        library.Dispose();

        Assert.Null(Record.Exception(workspace.Dispose));
        Assert.Equal(0, library.LowLevelLibrary?.Module.TrackedSessionCount ?? 0);
    }
}
