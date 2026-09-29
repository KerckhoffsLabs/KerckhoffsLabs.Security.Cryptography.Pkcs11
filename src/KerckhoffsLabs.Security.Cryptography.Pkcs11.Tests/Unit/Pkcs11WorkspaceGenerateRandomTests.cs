using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// <see cref="Pkcs11Workspace.GenerateRandom(Span{byte})"/> against the in-process token: it fills
/// the whole span, treats an empty span as a no-op the way <c>RandomNumberGenerator.Fill</c> does,
/// and refuses a disposed workspace.
/// </summary>
public sealed class Pkcs11WorkspaceGenerateRandomTests
{
    [Fact]
    public void FillsTheWholeSpan()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        Span<byte> destination = stackalloc byte[64];

        workspace.GenerateRandom(destination);

        // 64 random bytes leave neither half all-zero, except with negligible probability.
        Assert.True(destination[..32].ContainsAnyExcept((byte)0));
        Assert.True(destination[32..].ContainsAnyExcept((byte)0));
    }

    [Fact]
    public void EmptySpan_IsANoOp()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);

        Assert.Null(Record.Exception(() => workspace.GenerateRandom([])));
    }

    [Fact]
    public void AfterDispose_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        var workspace = ManagedToken.OpenWorkspace(library);
        workspace.Dispose();

        Assert.Throws<ObjectDisposedException>(() => workspace.GenerateRandom(new byte[8]));
    }
}
