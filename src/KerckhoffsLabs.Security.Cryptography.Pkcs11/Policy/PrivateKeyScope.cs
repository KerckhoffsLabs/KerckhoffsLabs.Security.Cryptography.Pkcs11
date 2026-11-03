namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>
/// The private keys an <see cref="KeyMaterialExportKind.EcdhSharedSecret"/> or
/// <see cref="KeyMaterialExportKind.KemSharedSecret"/> opt-in covers: the <c>privateKeys</c> argument of
/// <see cref="KeyMaterialExportRule.Allow"/>, which an opt-in to either kind must name.
/// </summary>
/// <remarks>
/// <para>
/// The secret an agreement or a decapsulation reads is a function of the private key and public inputs only: the
/// peer's public key, or the KEM ciphertext. Reading it over a long-lived private key turns that key into an oracle
/// for every session that key has protected. With a recorded peer public key, <c>Pkcs11Key.DeriveRawSecret</c> returns
/// the same Z that an earlier <c>Pkcs11Key.DeriveSecretAgreement</c> kept on the token, and with it every key derived
/// from Z. With a recorded ciphertext, an ML-KEM decapsulation returns the shared secret that
/// <c>Pkcs11Key.DecapsulateKey</c> kept on the token. The scope says which private keys that is acceptable for.
/// </para>
/// <para>
/// A KEM encapsulation uses no private key: its shared secret is fresh, so it is in every scope, <see cref="None"/>
/// included.
/// </para>
/// <para>
/// There is no default. <see cref="SessionObjects"/> covers ephemeral keys (the usual input of an ephemeral-static
/// agreement, or of a KEM exchange with a key pair made for it), as a session object goes with its session. It relies
/// on <c>CKA_TOKEN</c>, which no one can change on an existing object. A session copy of a token key would pass it,
/// but the library does not expose <c>C_CopyObject</c>. Keep a vendor tool or another library from copying
/// long-lived private keys into sessions whose policy allows these kinds, or set them <c>CKA_COPYABLE=false</c>.
/// </para>
/// </remarks>
public sealed class PrivateKeyScope
{
    private readonly Func<ExportKeyInfo, bool> _admits;

    private PrivateKeyScope(Func<ExportKeyInfo, bool> admits, string description)
    {
        _admits = admits;
        Description = description;
    }

    /// <summary>
    /// No private key: only a KEM encapsulation's fresh shared secret may be read. Refuses every agreement
    /// (<see cref="KeyMaterialExportKind.EcdhSharedSecret"/>) and every decapsulation.
    /// </summary>
    public static PrivateKeyScope None { get; } = new(_ => false, "no private key (encapsulation only)");

    /// <summary>
    /// Private keys that are session objects (<c>CKA_TOKEN</c> is <see langword="false"/>): ephemeral keys, which the
    /// token destroys when the session closes. See the remarks for what it relies on.
    /// </summary>
    public static PrivateKeyScope SessionObjects { get; } = new(
        k => !k.Token, "private keys that are session objects");

    /// <summary>
    /// Every private key the session can use, long-lived token keys included. Reading a secret over such a key
    /// reproduces what every earlier agreement or decapsulation with it kept on the token; name this only when that is
    /// the point.
    /// </summary>
    public static PrivateKeyScope Any { get; } = new(_ => true, "any private key");

    /// <summary>The private keys <paramref name="predicate"/> admits. It decides alone.</summary>
    /// <param name="predicate">Decides from what the library read off the private key; must not throw or call the token.</param>
    /// <param name="description">What the scope admits, for the policy catalogue; must not be blank.</param>
    /// <exception cref="ArgumentNullException"><paramref name="predicate"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="description"/> is blank.</exception>
    public static PrivateKeyScope Where(Func<ExportKeyInfo, bool> predicate, string description)
    {
        ArgumentNullException.ThrowIfNull(predicate);
        ArgumentException.ThrowIfNullOrWhiteSpace(description);
        return new(predicate, description.Trim());
    }

    /// <summary>What the scope admits, in a few words.</summary>
    public string Description { get; }

    /// <summary>Whether a read over <paramref name="privateKey"/> is in scope; a read with no private key always is.</summary>
    internal bool Admits(ExportKeyInfo? privateKey) => privateKey is null || _admits(privateKey);
}
