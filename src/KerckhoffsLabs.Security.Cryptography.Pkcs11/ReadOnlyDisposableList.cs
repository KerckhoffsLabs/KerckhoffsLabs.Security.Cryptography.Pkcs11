using System.Collections;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// A fixed collection of disposables that releases every element when it is disposed, so a returned
/// collection can be held by a <c>using</c> instead of a hand-written cleanup loop at each call site.
/// </summary>
/// <remarks>
/// <para>
/// The elements belong to this list from construction: it takes a snapshot of what it is given, and
/// disposing it disposes all of them. Nothing can be added or removed afterwards, which is what makes
/// that ownership claim safe to state — a caller cannot hand an element to something else and then
/// have this list free it underneath them.
/// </para>
/// <para>
/// <see cref="Dispose"/> releases <i>every</i> element even if one of them throws, rather than
/// stopping at the first failure. In this library disposing an attribute is what zeroizes and frees
/// the unmanaged buffer behind its value, so abandoning the rest of the list would leave key material
/// in memory — the outcome disposal exists to prevent. Failures are recorded in
/// <see cref="DisposalFailures"/> rather than thrown, so releasing the list can never displace the
/// exception that a <c>using</c> was already unwinding.
/// </para>
/// </remarks>
/// <typeparam name="T">Element type; every element is disposed by <see cref="Dispose"/>.</typeparam>
public sealed class ReadOnlyDisposableList<T> : IReadOnlyList<T>, IDisposable where T : IDisposable
{
    private readonly T[] _items;
    private List<Exception>? _failures;
    private bool _disposed;

    /// <summary>An empty list. Disposing it does nothing.</summary>
    public static ReadOnlyDisposableList<T> Empty { get; } = new([]);

    /// <summary>
    /// Creates a list holding a snapshot of <paramref name="items"/> and taking ownership of them.
    /// </summary>
    /// <param name="items">Elements whose ownership passes to this list.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="items"/> is <c>null</c>.</exception>
    public ReadOnlyDisposableList(IEnumerable<T> items)
    {
        ArgumentNullException.ThrowIfNull(items);
        _items = [.. items];
    }

    /// <summary>Gets the element at <paramref name="index"/>.</summary>
    /// <param name="index">Zero-based index.</param>
    /// <exception cref="ObjectDisposedException">Thrown if the list has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="index"/> is out of range.</exception>
    public T this[int index]
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _items[index];
        }
    }

    /// <summary>Number of elements.</summary>
    /// <exception cref="ObjectDisposedException">Thrown if the list has been disposed.</exception>
    public int Count
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _items.Length;
        }
    }

    /// <summary>Enumerates the elements.</summary>
    /// <remarks>
    /// Access after disposal throws rather than yielding disposed elements, matching
    /// <c>ObjectAttribute</c> and the rest of this library: reading a value whose buffer has been
    /// zeroized is a bug worth surfacing, not worth quietly returning zeroes for.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">Thrown if the list has been disposed.</exception>
    public IEnumerator<T> GetEnumerator()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return ((IEnumerable<T>)_items).GetEnumerator();
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    /// <summary>
    /// What went wrong during <see cref="Dispose"/>, in element order. Empty unless an element's
    /// <c>Dispose</c> threw.
    /// </summary>
    /// <remarks>
    /// Failures are recorded rather than thrown. Disposal usually runs from a <c>using</c>, and a
    /// throw there <i>replaces</i> an exception already in flight — so reporting a release failure
    /// that way would hide whatever actually went wrong, which is invariably the more useful of the
    /// two. The same reasoning governs the destroy-then-dispose helpers in this library.
    /// </remarks>
    public IReadOnlyList<Exception> DisposalFailures => _failures ?? [];

    /// <summary>
    /// Disposes every element. Disposing again is a no-op, and this never throws — see
    /// <see cref="DisposalFailures"/> for anything that went wrong.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        foreach (T item in _items)
        {
            try
            {
                item?.Dispose();
            }
            catch (Exception ex)
            {
                // Keep going: every element after this one still holds an unmanaged buffer, and
                // releasing those matters more than reporting this one promptly.
                (_failures ??= []).Add(ex);
            }
        }
    }
}
