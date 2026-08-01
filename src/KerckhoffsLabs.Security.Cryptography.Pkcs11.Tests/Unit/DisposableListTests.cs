namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// <see cref="DisposableList{T}"/> exists so a collection of disposables can be held by a
/// <c>using</c>. What it must not do is release only part of the collection.
/// </summary>
public sealed class DisposableListTests
{
    private sealed class Spy : IDisposable
    {
        public int Disposals;
        public bool ThrowOnDispose;

        public void Dispose()
        {
            Disposals++;
            if (ThrowOnDispose) throw new InvalidOperationException("spy");
        }
    }

    [Fact]
    public void Dispose_ReleasesEveryElement_AndEmptiesTheList()
    {
        Spy[] spies = [new(), new(), new()];
        var list = new DisposableList<Spy>(spies);

        list.Dispose();

        Assert.All(spies, s => Assert.Equal(1, s.Disposals));
        Assert.Empty(list);
    }

    /// <summary>
    /// The property the hand-written loops it replaces did not have. Here disposal is what zeroizes an
    /// attribute's unmanaged buffer, so stopping at the first failure would leave key material behind
    /// in exactly the situation disposal exists for.
    /// </summary>
    [Fact]
    public void Dispose_WhenAnElementThrows_StillReleasesTheRest()
    {
        Spy first = new();
        Spy bad = new() { ThrowOnDispose = true };
        Spy last = new();
        var list = new DisposableList<Spy>([first, bad, last]);

        var ex = Assert.Throws<AggregateException>(list.Dispose);

        Assert.Equal(1, first.Disposals);
        Assert.Equal(1, last.Disposals);   // reached despite the failure in between
        Assert.Single(ex.InnerExceptions);
        Assert.Empty(list);
    }

    [Fact]
    public void Dispose_ReportsEveryFailure_NotJustTheFirst()
    {
        var list = new DisposableList<Spy>(
            [new() { ThrowOnDispose = true }, new(), new() { ThrowOnDispose = true }]);

        var ex = Assert.Throws<AggregateException>(list.Dispose);

        Assert.Equal(2, ex.InnerExceptions.Count);
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        Spy spy = new();
        var list = new DisposableList<Spy>([spy]);

        list.Dispose();
        list.Dispose();

        Assert.Equal(1, spy.Disposals); // the second pass has nothing left to iterate
    }

    [Fact]
    public void Dispose_OnAnEmptyList_DoesNothing() =>
        Assert.Null(Record.Exception(new DisposableList<Spy>().Dispose));

    /// <summary>Deriving from List&lt;T&gt; is the point: it has to work where a List&lt;T&gt; is expected.</summary>
    [Fact]
    public void IsUsableAsAList()
    {
        using DisposableList<Spy> list = [new Spy()];
        list.AddRange([new Spy(), new Spy()]);

        List<Spy> asList = list;
        Assert.Equal(3, asList.Count);
    }

    /// <summary>
    /// The shape a public signature should hand back: disposable, and not modifiable by the caller.
    /// </summary>
    [Fact]
    public void IsUsableThroughTheReadOnlyInterface()
    {
        Spy[] spies = [new(), new()];
        IReadOnlyDisposableList<Spy> list = new DisposableList<Spy>(spies);

        Assert.Equal(2, list.Count);
        Assert.Same(spies[0], list[0]);

        list.Dispose();

        Assert.All(spies, s => Assert.Equal(1, s.Disposals));
    }
}
