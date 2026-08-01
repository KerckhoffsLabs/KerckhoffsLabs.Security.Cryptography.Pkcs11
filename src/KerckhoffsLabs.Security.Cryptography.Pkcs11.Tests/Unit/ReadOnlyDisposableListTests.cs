namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// <see cref="ReadOnlyDisposableList{T}"/> exists so a returned collection of disposables can be held
/// by a <c>using</c>. What it must not do is release only part of the collection.
/// </summary>
public sealed class ReadOnlyDisposableListTests
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
    public void Dispose_ReleasesEveryElement()
    {
        Spy[] spies = [new(), new(), new()];
        var list = new ReadOnlyDisposableList<Spy>(spies);

        list.Dispose();

        Assert.All(spies, s => Assert.Equal(1, s.Disposals));
    }

    /// <summary>
    /// The property the hand-written loops it replaces do not have. Here disposal is what zeroizes an
    /// attribute's unmanaged buffer, so stopping at the first failure would leave key material behind
    /// in exactly the situation disposal exists for.
    /// </summary>
    [Fact]
    public void Dispose_WhenAnElementThrows_StillReleasesTheRest()
    {
        Spy first = new();
        Spy bad = new() { ThrowOnDispose = true };
        Spy last = new();
        var list = new ReadOnlyDisposableList<Spy>([first, bad, last]);

        list.Dispose();

        Assert.Equal(1, first.Disposals);
        Assert.Equal(1, last.Disposals);   // reached despite the failure in between
        Assert.Single(list.DisposalFailures);
    }

    [Fact]
    public void Dispose_ReportsEveryFailure_NotJustTheFirst()
    {
        var list = new ReadOnlyDisposableList<Spy>(
            [new() { ThrowOnDispose = true }, new(), new() { ThrowOnDispose = true }]);

        list.Dispose();

        Assert.Equal(2, list.DisposalFailures.Count);
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        Spy spy = new();
        var list = new ReadOnlyDisposableList<Spy>([spy]);

        list.Dispose();
        list.Dispose();

        Assert.Equal(1, spy.Disposals);
    }

    /// <summary>
    /// Disposal never throws, however badly it goes. A <c>using</c> is usually unwinding when this
    /// runs, and a throw here would replace the exception that started the unwind — hiding the
    /// failure the caller actually needs to see behind one about releasing memory.
    /// </summary>
    [Fact]
    public void Dispose_NeverThrows_EvenWhenEveryElementFails()
    {
        var list = new ReadOnlyDisposableList<Spy>(
            [new() { ThrowOnDispose = true }, new() { ThrowOnDispose = true }]);

        Assert.Null(Record.Exception(list.Dispose));
        Assert.Null(Record.Exception(list.Dispose));   // and still not on a second pass

        Assert.Equal(2, list.DisposalFailures.Count);
    }

    [Fact]
    public void DisposalFailures_IsEmptyWhenNothingWentWrong()
    {
        var list = new ReadOnlyDisposableList<Spy>([new(), new()]);

        list.Dispose();

        Assert.Empty(list.DisposalFailures);
    }

    [Fact]
    public void ReadsAsAReadOnlyList()
    {
        Spy[] spies = [new(), new()];
        IReadOnlyList<Spy> list = new ReadOnlyDisposableList<Spy>(spies);

        Assert.Equal(2, list.Count);
        Assert.Same(spies[0], list[0]);
        Assert.Equal(spies, [.. list]);
    }

    /// <summary>
    /// Reading a value whose buffer has been zeroized is a bug worth surfacing, so access after
    /// disposal throws rather than handing back disposed elements — matching <c>ObjectAttribute</c>.
    /// </summary>
    [Fact]
    public void AccessAfterDispose_Throws()
    {
        var list = new ReadOnlyDisposableList<Spy>([new()]);
        list.Dispose();

        Assert.Throws<ObjectDisposedException>(() => list.Count);
        Assert.Throws<ObjectDisposedException>(() => list[0]);
        Assert.Throws<ObjectDisposedException>(() => list.GetEnumerator());
    }

    [Fact]
    public void Ctor_NullItems_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new ReadOnlyDisposableList<Spy>(null!));

    [Fact]
    public void Empty_IsUsableAndDisposesCleanly()
    {
        Assert.Empty(ReadOnlyDisposableList<Spy>.Empty);
        Assert.Null(Record.Exception(ReadOnlyDisposableList<Spy>.Empty.Dispose));
    }

    /// <summary>The snapshot is the ownership boundary: later changes to the source are not adopted.</summary>
    [Fact]
    public void Ctor_SnapshotsAGrowableSource()
    {
        List<Spy> source = [new()];
        var list = new ReadOnlyDisposableList<Spy>(source);

        Spy added = new();
        source.Add(added);
        list.Dispose();

        Assert.Equal(0, added.Disposals); // never owned, never released
    }

    /// <summary>
    /// An array source needs its own case: copying only when the source is not already a
    /// <c>T[]</c> is the obvious optimisation, and it would alias the caller's array — leaving what
    /// this list disposes at the mercy of whoever still holds it.
    /// </summary>
    [Fact]
    public void Ctor_SnapshotsAnArraySource()
    {
        Spy original = new();
        Spy[] source = [original];
        var list = new ReadOnlyDisposableList<Spy>(source);

        Spy swappedIn = new();
        source[0] = swappedIn;
        list.Dispose();

        Assert.Equal(1, original.Disposals);   // what the list was given
        Assert.Equal(0, swappedIn.Disposals);  // what the caller substituted afterwards
    }
}
