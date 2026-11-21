using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

public sealed class OwnedTests
{
    private sealed class Resource : IDisposable
    {
        public int DisposeCount { get; private set; }
        public void Dispose() => DisposeCount++;
    }

    [Fact]
    public void Value_ReturnsTheResource_WhileOwned()
    {
        var resource = new Resource();
        using var owned = new Owned<Resource>(resource);

        Assert.Same(resource, owned.Value);
        Assert.Equal(0, resource.DisposeCount);
    }

    [Fact]
    public void Dispose_DisposesTheResource_Once()
    {
        var resource = new Resource();
        var owned = new Owned<Resource>(resource);

        owned.Dispose();
        owned.Dispose();

        Assert.Equal(1, resource.DisposeCount);
    }

    [Fact]
    public void Release_HandsTheResourceOff_AndDisposeLeavesItAlone()
    {
        var resource = new Resource();
        var owned = new Owned<Resource>(resource);

        Assert.Same(resource, owned.Release());
        owned.Dispose();

        Assert.Equal(0, resource.DisposeCount);
    }

    [Fact]
    public void Value_AfterRelease_Throws()
    {
        using var owned = new Owned<Resource>(new Resource());
        owned.Release();

        Assert.Throws<InvalidOperationException>(() => owned.Value);
    }

    [Fact]
    public void Release_Twice_Throws()
    {
        using var owned = new Owned<Resource>(new Resource());
        owned.Release();

        Assert.Throws<InvalidOperationException>(() => owned.Release());
    }

    [Fact]
    public void ValueAndRelease_AfterDispose_Throw()
    {
        var resource = new Resource();
        var owned = new Owned<Resource>(resource);
        owned.Dispose();

        Assert.Throws<InvalidOperationException>(() => owned.Value);
        Assert.Throws<InvalidOperationException>(() => owned.Release());
        Assert.Equal(1, resource.DisposeCount);
    }
}
