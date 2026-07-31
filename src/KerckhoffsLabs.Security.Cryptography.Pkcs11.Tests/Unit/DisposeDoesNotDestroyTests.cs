using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// <c>Dispose</c> releases the managed wrapper and never destroys token state; <c>Destroy</c> is the
/// only member that calls <c>C_DestroyObject</c>.
/// </summary>
/// <remarks>
/// <para>
/// This is the invariant the whole ephemeral-vs-persistent question turns on. The wrapper cannot tell
/// a session object from a persistent key — <c>CKA_TOKEN</c> is set at creation from a runtime
/// template, or from the <c>persistOnToken</c> argument of the workspace factories — so an
/// auto-destroying <c>Dispose</c> would sometimes erase production key material and sometimes not,
/// decided by a value that isn't visible at the call site.
/// </para>
/// <para>
/// The two errors are not symmetric: destroying wrongly is irreversible, while failing to destroy a
/// session object costs nothing because PKCS#11 collects those at <c>C_CloseSession</c>. So disposal
/// stays inert. These tests assert what a caller can observe — whether the object is still on
/// the token afterwards — rather than counting calls into the module.
/// </para>
/// </remarks>
public sealed class DisposeDoesNotDestroyTests
{
    private static Pkcs11Workspace NewWorkspace(out Pkcs11Library library)
    {
        library = ManagedToken.NewLibrary();
        return ManagedToken.OpenWorkspace(library);
    }

    /// <summary>Is an object with this label still on the token?</summary>
    private static bool StillPresent(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        return workspace.FindObjects(filter).Count > 0;
    }

    [Fact]
    public void DisposingAKey_DoesNotDestroyItOnTheToken()
    {
        using var workspace = NewWorkspace(out var library);
        using (library)
        {
            var key = workspace.GenerateAesKey(256, label: "dispose-inert");

            key.Dispose();

            Assert.True(StillPresent(workspace, "dispose-inert"),
                "Dispose destroyed the token object; it must only release the managed wrapper.");
        }
    }

    [Fact]
    public void DestroyingAKey_DoesDestroyIt()
    {
        using var workspace = NewWorkspace(out var library);
        using (library)
        {
            using var key = workspace.GenerateAesKey(256, label: "destroy-works");

            key.Destroy();

            Assert.False(StillPresent(workspace, "destroy-works"));
        }
    }

    /// <summary>
    /// Destroy-then-Dispose is the shape every caller uses; the disposal must not attempt a second
    /// destroy of a handle that is already stale.
    /// </summary>
    [Fact]
    public void DestroyThenDispose_IsSafe()
    {
        using var workspace = NewWorkspace(out var library);
        using (library)
        {
            var key = workspace.GenerateAesKey(256, label: "destroy-then-dispose");

            key.Destroy();

            Assert.Null(Record.Exception(key.Dispose));
            Assert.False(StillPresent(workspace, "destroy-then-dispose"));
        }
    }

    /// <summary>
    /// The case an auto-destroying Dispose would ruin: a key the caller asked to persist must survive
    /// disposal of its wrapper.
    /// </summary>
    [Fact]
    public void DisposingAPersistentKey_LeavesItOnTheToken()
    {
        using var workspace = NewWorkspace(out var library);
        using (library)
        {
            using (var key = workspace.GenerateAesKey(256, label: "persistent", persistOnToken: true)) { }

            Assert.True(StillPresent(workspace, "persistent"),
                "Dispose destroyed a key the caller asked to persist on the token.");
        }
    }
}
