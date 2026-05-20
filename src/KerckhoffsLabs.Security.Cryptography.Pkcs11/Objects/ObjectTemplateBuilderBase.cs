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
    private bool _built;
    private bool _disposed;

    /// <summary>Sets an attribute. If the same CKA is already present, the previous value is disposed and replaced.</summary>
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
    public TSelf Attribute(CKA attribute, ulong value)
    {
        Set(new ObjectAttribute(attribute, value));
        return (TSelf)this;
    }

    /// <summary>Sets an arbitrary attribute as a bool value.</summary>
    public TSelf Attribute(CKA attribute, bool value)
    {
        Set(new ObjectAttribute(attribute, value));
        return (TSelf)this;
    }

    /// <summary>Sets an arbitrary attribute as a string value.</summary>
    public TSelf Attribute(CKA attribute, string value)
    {
        Set(new ObjectAttribute(attribute, value));
        return (TSelf)this;
    }

    /// <summary>Sets an arbitrary attribute as a byte buffer.</summary>
    public TSelf Attribute(CKA attribute, ReadOnlySpan<byte> value)
    {
        Set(new ObjectAttribute(attribute, value));
        return (TSelf)this;
    }

    /// <summary>Sets CKA_LABEL.</summary>
    public TSelf Label(string label) => Attribute(CKA.CKA_LABEL, label);

    /// <summary>Sets CKA_ID.</summary>
    public TSelf Id(ReadOnlySpan<byte> id) => Attribute(CKA.CKA_ID, id);

    /// <summary>Sets CKA_TOKEN (true = token object, false = session object).</summary>
    public TSelf OnToken(bool value = true) => Attribute(CKA.CKA_TOKEN, value);

    /// <summary>Finalises the builder and returns an owning <see cref="ObjectTemplate"/>.
    /// The builder cannot be reused after this call — start a new builder for a new template.</summary>
    public ObjectTemplate Build()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_built) throw new InvalidOperationException("Builder has already produced an ObjectTemplate. Start a new builder.");

        var list = new List<ObjectAttribute>(_attributes.Values);
        _attributes.Clear(); // ownership transferred to the ObjectTemplate
        _built = true;
        return new ObjectTemplate(list);
    }

    /// <summary>Disposes any attributes the builder still owns. Safe to call before <see cref="Build"/>.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        foreach (var attr in _attributes.Values) attr.Dispose();
        _attributes.Clear();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer safety net.</summary>
    ~ObjectTemplateBuilderBase() => Dispose();
}
