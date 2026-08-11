using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

/// <summary>
/// An immutable, owning collection of <see cref="ObjectAttribute"/> values describing a
/// PKCS#11 object — used as the input template for create / generate / find operations.
/// </summary>
/// <remarks>
/// Build instances through the fluent factories on this class
/// (<see cref="ForSecretKey(CKK)"/>, <see cref="ForPrivateKey(CKK)"/>, etc.). Disposing
/// the template disposes every <see cref="ObjectAttribute"/> it owns and releases the
/// associated unmanaged buffers.
/// </remarks>
public sealed class ObjectTemplate : IDisposable
{
    private readonly List<ObjectAttribute> _attributes;
    private readonly List<ObjectTemplate> _nested;
    private bool _disposed;

    internal ObjectTemplate(List<ObjectAttribute> attributes, List<ObjectTemplate>? nested = null)
    {
        _attributes = attributes;
        _nested = nested ?? [];
    }

    /// <summary>Number of attributes in the template.</summary>
    public int Count => _attributes.Count;

    /// <summary>Internal accessor used by call sites that marshal the template to PKCS#11.</summary>
    internal IReadOnlyList<ObjectAttribute> Attributes => _attributes;

    /// <summary>
    /// Test seam: the nested child templates this template owns. A nested attribute
    /// (<c>CKA_WRAP_TEMPLATE</c> and friends) is a flat copy of these children's
    /// <c>CK_ATTRIBUTE</c> structs, pointers included, so holding them here is what keeps those
    /// pointers valid and their targets un-finalized for as long as this template lives.
    /// </summary>
    internal IReadOnlyList<ObjectTemplate> NestedChildren => _nested;

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        foreach (var attr in _attributes) attr.Dispose();
        _attributes.Clear();
        // Nested children come last: the parent's flat copy holds pointers into buffers these own,
        // so they stay valid for as long as anything could still marshal the parent.
        foreach (var child in _nested) child.Dispose();
        _nested.Clear();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer safety net — releases unmanaged buffers if Dispose was not called.</summary>
    ~ObjectTemplate() => Dispose();

    /// <summary>Begins a fluent template for a secret (symmetric) key of the given type.</summary>
    public static SecretKeyTemplateBuilder ForSecretKey(CKK keyType) => new(keyType);

    /// <summary>Begins a fluent template for an asymmetric private key of the given type.</summary>
    public static PrivateKeyTemplateBuilder ForPrivateKey(CKK keyType) => new(keyType);

    /// <summary>Begins a fluent template for an asymmetric public key of the given type.</summary>
    public static PublicKeyTemplateBuilder ForPublicKey(CKK keyType) => new(keyType);

    /// <summary>Begins a fluent template for a certificate of the given type.</summary>
    public static CertificateTemplateBuilder ForCertificate(CKC certType) => new(certType);

    /// <summary>Begins a fluent template for a data object.</summary>
    public static DataTemplateBuilder ForData() => new();

    /// <summary>Begins a fluent template with no preset attributes. Escape hatch.</summary>
    public static GenericTemplateBuilder Empty() => new();
}
