using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// <see cref="Pkcs11Session.GenerateRandom(Span{byte})"/> against the in-process token: it fills
/// the whole span, treats an empty span as a no-op the way <c>RandomNumberGenerator.Fill</c> does,
/// and refuses a disposed session.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11SessionGenerateRandomTests
{
    [Fact]
    public void FillsTheWholeSpan()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        Span<byte> destination = stackalloc byte[64];

        session.GenerateRandom(destination);

        // 64 random bytes leave neither half all-zero, except with negligible probability.
        Assert.True(destination[..32].ContainsAnyExcept((byte)0));
        Assert.True(destination[32..].ContainsAnyExcept((byte)0));
    }

    [Fact]
    public void EmptySpan_IsANoOp()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);

        Assert.Null(Record.Exception(() => session.GenerateRandom([])));
    }

    [Fact]
    public void AfterDispose_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        var session = ManagedToken.OpenSession(library);
        session.Dispose();

        Assert.Throws<ObjectDisposedException>(() => session.GenerateRandom(new byte[8]));
    }
}
