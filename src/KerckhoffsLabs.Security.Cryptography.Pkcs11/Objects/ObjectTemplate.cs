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
    private bool _disposed;

    internal ObjectTemplate(List<ObjectAttribute> attributes)
    {
        _attributes = attributes;
    }

    /// <summary>Number of attributes in the template.</summary>
    public int Count => _attributes.Count;

    /// <summary>Internal accessor used by call sites that marshal the template to PKCS#11.</summary>
    internal IReadOnlyList<ObjectAttribute> Attributes => _attributes;

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        foreach (var attr in _attributes) attr.Dispose();
        _attributes.Clear();
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
