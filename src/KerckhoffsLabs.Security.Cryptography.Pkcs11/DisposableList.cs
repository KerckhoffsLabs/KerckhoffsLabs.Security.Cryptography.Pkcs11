namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// A <see cref="List{T}"/> of disposables that releases every element when it is disposed, so a
/// collection of them can be held by a <c>using</c> instead of a hand-written cleanup loop.
/// </summary>
/// <remarks>
/// <para>
/// Deriving from <see cref="List{T}"/> rather than wrapping one is deliberate: the collections this
/// replaces are already <see cref="List{T}"/> values flowing through the API, so a derived type drops
/// in where a wrapper would break every consumer. The cost is the usual one — <see cref="List{T}"/>
/// declares no virtual members, so this type cannot observe an element being added or removed, and an
/// element's ownership passes here the moment it is added.
/// </para>
/// <para>
/// <see cref="Dispose"/> releases <i>every</i> element even if one of them throws, rather than
/// stopping at the first failure. In this library disposing an attribute is what zeroizes and frees
/// the unmanaged buffer behind its value, so abandoning the rest of the list would leave key material
/// in memory — the outcome disposal exists to prevent. Failures are collected and reported together,
/// after the list has been fully released.
/// </para>
/// <para>
/// Prefer <see cref="IReadOnlyDisposableList{T}"/> on a public signature: this type is a
/// <see cref="List{T}"/>, so returning it hands the caller mutation they were not offered. Build one
/// here, return the interface.
/// </para>
/// </remarks>
/// <typeparam name="T">Element type; every element is disposed by <see cref="Dispose"/>.</typeparam>
public class DisposableList<T> : List<T>, IReadOnlyDisposableList<T> where T : IDisposable
{
    /// <summary>Creates an empty list.</summary>
    public DisposableList() { }

    /// <summary>Creates a list holding <paramref name="collection"/>, taking ownership of its elements.</summary>
    /// <param name="collection">Elements whose ownership passes to this list.</param>
    public DisposableList(IEnumerable<T> collection) : base(collection) { }

    /// <summary>
    /// Disposes every element, then empties the list. Disposing again is a no-op, because the second
    /// call has nothing left to iterate.
    /// </summary>
    /// <exception cref="AggregateException">
    /// Thrown if any element's <c>Dispose</c> threw. Every element is disposed first, so this reports
    /// what went wrong rather than deciding how much of the list gets released.
    /// </exception>
    public void Dispose()
    {
        List<Exception>? failures = null;

        foreach (T item in this)
        {
            try
            {
                item?.Dispose();
            }
            catch (Exception ex)
            {
                // Keep going: every element after this one still holds an unmanaged buffer.
                (failures ??= []).Add(ex);
            }
        }

        Clear();
        GC.SuppressFinalize(this);

        if (failures is not null)
            throw new AggregateException("One or more elements failed to dispose.", failures);
    }
}
