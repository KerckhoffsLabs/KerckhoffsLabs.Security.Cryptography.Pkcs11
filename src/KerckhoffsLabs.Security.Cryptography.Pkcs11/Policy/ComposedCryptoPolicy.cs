using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>
/// A policy assembled from reusable rules by <see cref="CryptoPolicyBuilder"/>: deny by default, an allow-list of
/// mechanisms (each with an optional <see cref="MechanismCheck"/>), hashes, curves and key-agreement KDFs and
/// key types, plus <see cref="RsaKeyGenerationRule"/>, <see cref="KeyTemplateRule"/> and <see cref="SecretExportRule"/>.
/// <see cref="CryptoPolicy.Recommended"/> and <see cref="CryptoPolicy.NistApproved"/> are built this way.
/// </summary>
public sealed class ComposedCryptoPolicy : ICryptoPolicy
{
    internal ComposedCryptoPolicy(string name, bool allowsOverride, PolicyCatalogue catalogue)
    {
        Name = name;
        AllowsOverride = allowsOverride;
        Catalogue = catalogue;
    }

    /// <inheritdoc/>
    public string Name { get; }

    /// <inheritdoc/>
    public bool AllowsOverride { get; }

    /// <summary>The allow-lists, rules and documented refusals this policy evaluates.</summary>
    internal PolicyCatalogue Catalogue { get; }

    /// <inheritdoc/>
    public PolicyDecision Evaluate(PolicyRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return CatalogueEvaluator.Evaluate(Catalogue, Name, request);
    }

    /// <summary>
    /// Starts a new policy named <paramref name="name"/> holding a copy of every rule of this one, including
    /// <see cref="AllowsOverride"/>. This policy is not modified.
    /// </summary>
    /// <param name="name">The new policy's name; not <c>"Recommended"</c> or <c>"NistApproved"</c>.</param>
    /// <exception cref="ArgumentException"><paramref name="name"/> is blank or reserved.</exception>
    public CryptoPolicyBuilder ToBuilder(string name) => CryptoPolicyBuilder.CopyOf(this, name);

    /// <inheritdoc/>
    public override string ToString() => Name;
}
