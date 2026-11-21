namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// A disposable this scope owns until it hands it off: disposing the <see cref="Owned{T}"/> disposes
/// <see cref="Value"/>, unless <see cref="Release"/> passed it to a new owner first. For a <see langword="using"/>
/// declaration around a resource that is closed on every path but the one that keeps it.
/// </summary>
/// <typeparam name="T">The resource's type.</typeparam>
internal sealed class Owned<T>(T value) : IDisposable
    where T : class, IDisposable
{
    private T? _value = value;

    /// <summary>An owner with nothing to own yet: for a resource acquired later in the scope (see <see cref="Own"/>).</summary>
    public Owned()
        : this(null!)
    {
    }

    /// <summary>The resource, while this scope still owns it.</summary>
    /// <exception cref="InvalidOperationException">It was handed off (<see cref="Release"/>).</exception>
    public T Value => _value ?? throw new InvalidOperationException("The resource was handed off.");

    /// <summary>Hands the resource off: returns it, and disposing this no longer disposes it.</summary>
    /// <exception cref="InvalidOperationException">It was handed off already.</exception>
    public T Release()
        => Interlocked.Exchange(ref _value, null) ?? throw new InvalidOperationException("The resource was handed off.");

    /// <summary>Takes ownership of <paramref name="value"/>, for an owner made with nothing to own yet.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="value"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">This owner owns a resource already.</exception>
    public void Own(T value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (Interlocked.CompareExchange(ref _value, value, null) is not null)
            throw new InvalidOperationException("This owner owns a resource already.");
    }

    /// <summary>Disposes the resource, unless it was handed off.</summary>
    public void Dispose() => Interlocked.Exchange(ref _value, null)?.Dispose();
}
