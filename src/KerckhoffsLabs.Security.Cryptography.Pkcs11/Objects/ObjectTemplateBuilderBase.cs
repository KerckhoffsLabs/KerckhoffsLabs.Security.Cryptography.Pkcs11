using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

/// <summary>
/// Shared base for fluent template builders. Uses the curiously-recurring template pattern
/// so each subclass returns its own type from fluent calls and method chaining keeps the
/// caller in the specific builder's API surface.
/// </summary>
/// <typeparam name="TSelf">The concrete builder type — passed for fluent return values.</typeparam>
public abstract class ObjectTemplateBuilderBase<TSelf> : IDisposable
    where TSelf : ObjectTemplateBuilderBase<TSelf>
{
    // Dictionary keyed by CKA so "last write wins" replaces an earlier attribute rather
    // than appending — matches PKCS#11 v3.1 §5.5.6 semantics. We own the ObjectAttribute
    // values and must dispose the displaced one on replacement.
    private readonly Dictionary<CKA, ObjectAttribute> _attributes = [];
    // Nested templates (CKA_WRAP_TEMPLATE and friends) whose children this builder owns until
    // Build hands them to the ObjectTemplate. Keyed by CKA so a second call replaces cleanly.
    private readonly Dictionary<CKA, ObjectTemplate> _nested = [];
    private bool _built;
    private bool _disposed;

    /// <summary>Sets an attribute. If the same CKA is already present, the previous value is disposed and replaced.</summary>
    /// <exception cref="ObjectDisposedException">Thrown if the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the builder has already produced an <see cref="ObjectTemplate"/>.</exception>
    protected void Set(ObjectAttribute attr)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_built) throw new InvalidOperationException("Builder has already produced an ObjectTemplate. Start a new builder.");

        var key = (CKA)attr.Type;
        if (_attributes.TryGetValue(key, out var existing))
            existing.Dispose();
        _attributes[key] = attr;
    }

    /// <summary>Sets an arbitrary attribute as a ulong value. Escape hatch for attributes the typed API does not cover.</summary>
    /// <exception cref="ObjectDisposedException">Thrown if the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the builder has already produced an <see cref="ObjectTemplate"/>.</exception>
    public TSelf Attribute(CKA attribute, ulong value)
    {
        Set(new ObjectAttribute(attribute, value));
        return (TSelf)this;
    }

    /// <summary>Sets an arbitrary attribute as a bool value.</summary>
    /// <exception cref="ObjectDisposedException">Thrown if the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the builder has already produced an <see cref="ObjectTemplate"/>.</exception>
    public TSelf Attribute(CKA attribute, bool value)
    {
        Set(new ObjectAttribute(attribute, value));
        return (TSelf)this;
    }

    /// <summary>Sets an arbitrary attribute as a string value.</summary>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="value"/> is <c>null</c>.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the builder has already produced an <see cref="ObjectTemplate"/>.</exception>
    public TSelf Attribute(CKA attribute, string value)
    {
        Set(new ObjectAttribute(attribute, value));
        return (TSelf)this;
    }

    /// <summary>Sets an arbitrary attribute as a byte buffer.</summary>
    /// <exception cref="ObjectDisposedException">Thrown if the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the builder has already produced an <see cref="ObjectTemplate"/>.</exception>
    public TSelf Attribute(CKA attribute, ReadOnlySpan<byte> value)
    {
        Set(new ObjectAttribute(attribute, value));
        return (TSelf)this;
    }

    /// <summary>
    /// Sets a nested-template attribute (<c>CKA_WRAP_TEMPLATE</c>, <c>CKA_UNWRAP_TEMPLATE</c>,
    /// <c>CKA_DERIVE_TEMPLATE</c>) from a configuration callback.
    /// </summary>
    /// <remarks>
    /// The children are marshalled as flat copies of their <c>CK_ATTRIBUTE</c> structs, pointers
    /// included, so this builder keeps the child template alive and hands ownership to the
    /// <see cref="ObjectTemplate"/> at <see cref="Build"/>. The caller never sees a disposable child.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="configure"/> is <c>null</c>.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the builder has already produced an <see cref="ObjectTemplate"/>.</exception>
    protected TSelf NestedTemplate(CKA attribute, Action<NestedKeyTemplateBuilder> configure)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_built) throw new InvalidOperationException("Builder has already produced an ObjectTemplate. Start a new builder.");
        ArgumentNullException.ThrowIfNull(configure);

        using var inner = new NestedKeyTemplateBuilder();
        configure(inner);
        ObjectTemplate child = inner.Build();

        try
        {
            Set(new ObjectAttribute(attribute, [.. child.Attributes]));
        }
        catch
        {
            child.Dispose();
            throw;
        }

        // Set has already disposed any displaced parent attribute; drop the children it pointed at.
        if (_nested.Remove(attribute, out ObjectTemplate? displaced))
            displaced.Dispose();
        _nested[attribute] = child;

        return (TSelf)this;
    }

    /// <summary>Sets CKA_LABEL.</summary>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="label"/> is <c>null</c>.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the builder has already produced an <see cref="ObjectTemplate"/>.</exception>
    public TSelf Label(string label) => Attribute(CKA.CKA_LABEL, label);

    /// <summary>Sets CKA_ID.</summary>
    /// <exception cref="ObjectDisposedException">Thrown if the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the builder has already produced an <see cref="ObjectTemplate"/>.</exception>
    public TSelf Id(ReadOnlySpan<byte> id) => Attribute(CKA.CKA_ID, id);

    /// <summary>Sets CKA_TOKEN (true = token object, false = session object).</summary>
    /// <exception cref="ObjectDisposedException">Thrown if the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the builder has already produced an <see cref="ObjectTemplate"/>.</exception>
    public TSelf OnToken(bool value = true) => Attribute(CKA.CKA_TOKEN, value);

    /// <summary>Finalises the builder and returns an owning <see cref="ObjectTemplate"/>.
    /// The builder cannot be reused after this call — start a new builder for a new template.</summary>
    /// <exception cref="ObjectDisposedException">Thrown if the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the builder has already produced an <see cref="ObjectTemplate"/>.</exception>
    public ObjectTemplate Build()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_built) throw new InvalidOperationException("Builder has already produced an ObjectTemplate. Start a new builder.");

        List<ObjectAttribute> list = [.. _attributes.Values];
        List<ObjectTemplate> nested = [.. _nested.Values];
        _attributes.Clear(); // ownership transferred to the ObjectTemplate
        _nested.Clear();
        _built = true;
        return new ObjectTemplate(list, nested);
    }

    /// <summary>
    /// Test seam: how many nested templates this builder still owns. Zero once <see cref="Build"/>
    /// has transferred them to the produced <see cref="ObjectTemplate"/>.
    /// </summary>
    internal int NestedTemplateCount => _nested.Count;

    /// <summary>Disposes any attributes the builder still owns. Safe to call before <see cref="Build"/>.</summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Disposes the attributes the builder still owns. The builder holds only managed
    /// <see cref="ObjectAttribute"/> values — each with its own finalizer — so cleanup runs only on
    /// the deterministic (<paramref name="disposing"/> = <see langword="true"/>) path and this type
    /// needs no finalizer of its own.
    /// </summary>
    /// <param name="disposing"><see langword="true"/> when called from <see cref="Dispose()"/>.</param>
    protected virtual void Dispose(bool disposing)
    {
        if (_disposed) return;
        if (disposing)
        {
            foreach (var attr in _attributes.Values) attr.Dispose();
            _attributes.Clear();
            foreach (var child in _nested.Values) child.Dispose();
            _nested.Clear();
        }
        _disposed = true;
    }
}
