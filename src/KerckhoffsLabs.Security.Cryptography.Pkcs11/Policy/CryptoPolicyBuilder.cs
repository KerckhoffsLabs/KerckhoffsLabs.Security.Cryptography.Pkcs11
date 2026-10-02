using System.Collections.Frozen;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>
/// Assembles a <see cref="ComposedCryptoPolicy"/> from reusable rules. Start empty with
/// <see cref="CryptoPolicyBuilder(string)"/> or from an existing policy with
/// <see cref="ComposedCryptoPolicy.ToBuilder(string)"/>, then call <see cref="Build"/>.
/// </summary>
/// <remarks>
/// A new builder denies everything and applies <see cref="RsaKeyGenerationRule.Minimum(int)"/> (2048),
/// <see cref="KeyTemplateRule.RequireSensitive()"/> and <see cref="SecretExportRule.Refuse()"/>.
/// <see cref="Build"/> takes a snapshot: later changes to the builder never affect a built policy.
/// </remarks>
public sealed class CryptoPolicyBuilder
{
    private static readonly string[] ReservedNames = ["Recommended", "NistApproved"];

    private readonly string _name;
    private bool _allowsOverride = true;
    private readonly Dictionary<CKM, MechanismRule> _mechanisms = [];
    private readonly Dictionary<ulong, MechanismRule> _vendorMechanisms = [];
    private readonly Dictionary<string, AllowedHash> _hashes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _curves = new(StringComparer.Ordinal);
    private readonly Dictionary<CKD, string> _kdfs = [];
    private readonly Dictionary<CKK, string> _keyAgreementKeyTypes = [];
    private readonly Dictionary<SecretExportKind, string> _secretExports = [];
    private readonly Dictionary<CKM, DocumentedRefusal> _refusedMechanisms = [];
    private readonly Dictionary<string, DocumentedRefusal> _refusedHashes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DocumentedRefusal> _refusedCurves = new(StringComparer.Ordinal);
    private readonly Dictionary<CKD, DocumentedRefusal> _refusedKdfs = [];
    private readonly Dictionary<CKK, DocumentedRefusal> _refusedKeyAgreementKeyTypes = [];
    private readonly Dictionary<string, DocumentedRefusal> _refusedPrfs = new(StringComparer.Ordinal);
    private RsaKeyGenerationRule _rsaKeyGeneration = RsaKeyGenerationRule.Minimum(2048);
    private KeyTemplateRule _keyTemplate = KeyTemplateRule.RequireSensitive();
    private SecretExportRule _secretExport = SecretExportRule.Refuse();
    private Func<PolicyIdentity, string>? _unlistedMechanismHint;
    private string? _builtInReference;
    private string? _legacyUseHint;
    private PolicyDocumentation _documentation;

    /// <summary>Starts an empty policy named <paramref name="name"/>, which denies everything until you allow it.</summary>
    /// <param name="name">The policy's name; not <c>"Recommended"</c> or <c>"NistApproved"</c>.</param>
    /// <exception cref="ArgumentException"><paramref name="name"/> is blank or reserved.</exception>
    public CryptoPolicyBuilder(string name) => _name = ValidateName(name);

    private CryptoPolicyBuilder(string name, bool _) => _name = name;

    /// <summary>A builder for a built-in policy, allowed to take a reserved name.</summary>
    internal static CryptoPolicyBuilder ForBuiltIn(string reservedName) => new(reservedName, true);

    internal static CryptoPolicyBuilder CopyOf(ComposedCryptoPolicy source, string name)
    {
        var b = new CryptoPolicyBuilder(ValidateName(name), true) { _allowsOverride = source.AllowsOverride };
        PolicyCatalogue c = source.Catalogue;
        Copy(c.AllowedMechanisms, b._mechanisms);
        Copy(c.AllowedVendorMechanisms, b._vendorMechanisms);
        Copy(c.AllowedHashes, b._hashes);
        Copy(c.AllowedCurves, b._curves);
        Copy(c.AllowedKdfs, b._kdfs);
        Copy(c.AllowedKeyAgreementKeyTypes, b._keyAgreementKeyTypes);
        Copy(c.AllowedSecretExports, b._secretExports);
        Copy(c.DocumentedRefusedMechanisms, b._refusedMechanisms);
        Copy(c.DocumentedRefusedHashes, b._refusedHashes);
        Copy(c.DocumentedRefusedCurves, b._refusedCurves);
        Copy(c.DocumentedRefusedKdfs, b._refusedKdfs);
        Copy(c.DocumentedRefusedKeyAgreementKeyTypes, b._refusedKeyAgreementKeyTypes);
        Copy(c.DocumentedRefusedPrfs, b._refusedPrfs);
        b._rsaKeyGeneration = c.RsaKeyGeneration;
        b._keyTemplate = c.KeyTemplate;
        b._secretExport = c.SecretExport;
        b._unlistedMechanismHint = c.UnlistedMechanismHint;
        b._legacyUseHint = c.LegacyUseHint;
        return b;
    }

    /// <summary>Sets whether a workspace opened under the built policy accepts <c>UsePolicy</c> overrides.</summary>
    /// <param name="allows"><see langword="true"/> to accept overrides.</param>
    public CryptoPolicyBuilder AllowsOverride(bool allows)
    {
        _allowsOverride = allows;
        return this;
    }

    /// <summary>
    /// Allows <paramref name="mechanism"/> for <paramref name="operations"/>. On a mechanism already allowed, adds
    /// the operations and keeps its existing <see cref="MechanismCheck"/>; the rationale is replaced.
    /// </summary>
    /// <param name="mechanism">The mechanism; a vendor mechanism is its value cast to <see cref="CKM"/>.</param>
    /// <param name="operations">The operations to allow; at least one.</param>
    /// <param name="rationale">Why it is allowed; shown when a request for another operation is denied.</param>
    /// <param name="check">A check on the mechanism's parameters, or <see langword="null"/> for none.</param>
    /// <exception cref="ArgumentException"><paramref name="operations"/> is empty, <paramref name="rationale"/> is
    /// blank, <paramref name="check"/> differs from the check the mechanism already has (remove it first), or an ECDH
    /// mechanism (<c>CKM_ECDH1_DERIVE</c>, <c>CKM_ECDH1_COFACTOR_DERIVE</c>) would have no check — it needs
    /// <see cref="MechanismChecks.Ecdh1DeriveParams"/> for the key-agreement KDF allow-list to apply.</exception>
    /// <remarks>
    /// <c>CKM_RSA_PKCS_OAEP</c> without <see cref="MechanismChecks.OaepHash"/> lets the token choose the OAEP hash
    /// (typically SHA-1); attach the check unless you mean that.
    /// </remarks>
    public CryptoPolicyBuilder AllowMechanism(CKM mechanism, IEnumerable<CryptoOperation> operations, string rationale, MechanismCheck? check = null) =>
        AllowMechanism(mechanism, ToFlags(operations), rationale, check);

    /// <summary>
    /// Allows <paramref name="mechanism"/> for <paramref name="operations"/> as legacy use only — verifying an old
    /// signature or decrypting old data — reported as such in denials. Widening behaves as for <see cref="AllowMechanism(CKM, IEnumerable{CryptoOperation}, string, MechanismCheck?)"/>.
    /// </summary>
    /// <param name="mechanism">The mechanism.</param>
    /// <param name="operations">The legacy operations to allow; at least one.</param>
    /// <param name="rationale">Why it is allowed.</param>
    /// <param name="check">A check on the mechanism's parameters, or <see langword="null"/> for none.</param>
    /// <exception cref="ArgumentException">As for <see cref="AllowMechanism(CKM, IEnumerable{CryptoOperation}, string, MechanismCheck?)"/>.</exception>
    public CryptoPolicyBuilder AllowMechanismForLegacyUse(CKM mechanism, IEnumerable<CryptoOperation> operations, string rationale, MechanismCheck? check = null) =>
        AllowMechanismForLegacyUse(mechanism, ToFlags(operations), rationale, check);

    internal CryptoPolicyBuilder AllowMechanism(CKM mechanism, CryptoOperations operations, string rationale, MechanismCheck? check) =>
        Upsert(mechanism, operations, CryptoOperations.None, rationale, check);

    internal CryptoPolicyBuilder AllowMechanismForLegacyUse(CKM mechanism, CryptoOperations operations, string rationale, MechanismCheck? check) =>
        Upsert(mechanism, CryptoOperations.None, operations, rationale, check);

    private CryptoPolicyBuilder Upsert(CKM mechanism, CryptoOperations operations, CryptoOperations legacy, string rationale, MechanismCheck? check)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rationale);
        // The session refuses it whatever the policy: allowing it would document a permission that never applies.
        if (mechanism == CKM.CKM_HKDF_DATA)
            throw new ArgumentException(
                "CKM_HKDF_DATA writes the KDF output to a data object in the clear, and every session refuses it " +
                "whatever the policy. Allow CKM_HKDF_DERIVE instead.", nameof(mechanism));
        if (_refusedMechanisms.TryGetValue(mechanism, out DocumentedRefusal? refusal) && ReferenceEquals(refusal, RemovedRefusal))
            _refusedMechanisms.Remove(mechanism);
        if (mechanism >= CKM.CKM_VENDOR_DEFINED)
            Upsert(_vendorMechanisms, (ulong)mechanism, mechanism, operations, legacy, rationale, check);
        else
            Upsert(_mechanisms, mechanism, mechanism, operations, legacy, rationale, check);
        return this;
    }

    private static void Upsert<TKey>(Dictionary<TKey, MechanismRule> table, TKey key, CKM mechanism,
        CryptoOperations operations, CryptoOperations legacy, string rationale, MechanismCheck? check) where TKey : notnull
    {
        if (!table.TryGetValue(key, out MechanismRule? existing))
        {
            RequireEcdhCheck(mechanism, check);
            table[key] = new MechanismRule(operations, legacy, check, rationale);
            return;
        }
        if (check is not null && existing.ParameterCheck is not null && !check.Equals(existing.ParameterCheck))
            throw new ArgumentException(
                $"{mechanism} already has a parameter check ({existing.ParameterCheck.Description}); remove the mechanism first to replace it.",
                nameof(check));
        table[key] = new MechanismRule(existing.Operations | operations, existing.LegacyOperations | legacy,
            existing.ParameterCheck ?? check, rationale);
    }

    // ECDH with parameters the library cannot read (raw bytes) never reaches the key-agreement KDF allow-list,
    // which the session judges only from CkmEcdh1DeriveParams; an ECDH entry therefore needs the check that
    // refuses anything else.
    private static void RequireEcdhCheck(CKM mechanism, MechanismCheck? check)
    {
        if (check is null && mechanism is CKM.CKM_ECDH1_DERIVE or CKM.CKM_ECDH1_COFACTOR_DERIVE)
            throw new ArgumentException(
                $"{mechanism} needs MechanismChecks.Ecdh1DeriveParams(); without it, ECDH with raw parameter bytes would bypass the key-agreement KDF allow-list.",
                nameof(check));
    }

    /// <summary>Removes <paramref name="mechanism"/> from the allow-list, if present.</summary>
    /// <param name="mechanism">The mechanism to remove.</param>
    /// <remarks>
    /// A removed mechanism is denied as removed ("This policy removed it from its allow-list."), not as unreviewed:
    /// it was reviewed and deliberately dropped. Allowing it again restores it.
    /// </remarks>
    public CryptoPolicyBuilder RemoveMechanism(CKM mechanism)
    {
        bool removed = mechanism >= CKM.CKM_VENDOR_DEFINED
            ? _vendorMechanisms.Remove((ulong)mechanism)
            : _mechanisms.Remove(mechanism);
        if (removed)
            _refusedMechanisms.TryAdd(mechanism, RemovedRefusal);
        return this;
    }

    /// <summary>The documented refusal <see cref="RemoveMechanism"/> records for a mechanism it removed.</summary>
    /// <summary>The refusal of a mechanism this policy removed: the caller's own choice, so it carries no legacy hint.</summary>
    internal static readonly DocumentedRefusal RemovedRefusal = new("This policy removed it from its allow-list.", null);

    /// <summary>Allows <paramref name="hash"/> for <paramref name="operations"/> (a <see cref="HashUseRequest"/>).</summary>
    /// <param name="hash">The hash.</param>
    /// <param name="operations">The operations to allow; at least one.</param>
    /// <param name="rationale">Why it is allowed.</param>
    /// <exception cref="ArgumentException"><paramref name="hash"/> has no name, <paramref name="operations"/> is empty,
    /// or <paramref name="rationale"/> is blank.</exception>
    public CryptoPolicyBuilder AllowHash(HashAlgorithmName hash, IEnumerable<CryptoOperation> operations, string rationale) =>
        AllowHash(HashName(hash), ToFlags(operations), rationale);

    internal CryptoPolicyBuilder AllowHash(string name, CryptoOperations operations, string rationale)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rationale);
        _hashes[name] = new AllowedHash(operations, rationale);
        return this;
    }

    /// <summary>Removes <paramref name="hash"/>, if allowed.</summary>
    /// <param name="hash">The hash to remove.</param>
    public CryptoPolicyBuilder RemoveHash(HashAlgorithmName hash)
    {
        _hashes.Remove(HashName(hash));
        return this;
    }

    /// <summary>Allows generating EC keys on <paramref name="curve"/>.</summary>
    /// <param name="curve">The curve; it must have an OID.</param>
    /// <param name="rationale">Why it is allowed.</param>
    /// <exception cref="ArgumentException"><paramref name="curve"/> has no OID, or <paramref name="rationale"/> is blank.</exception>
    public CryptoPolicyBuilder AllowCurve(Pkcs11ECCurve curve, string rationale) => AllowCurve(CurveOid(curve), rationale);

    internal CryptoPolicyBuilder AllowCurve(string oid, string rationale)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rationale);
        _curves[oid] = rationale;
        return this;
    }

    /// <summary>Removes <paramref name="curve"/>, if allowed.</summary>
    /// <param name="curve">The curve to remove.</param>
    public CryptoPolicyBuilder RemoveCurve(Pkcs11ECCurve curve)
    {
        _curves.Remove(CurveOid(curve));
        return this;
    }

    /// <summary>
    /// Allows <paramref name="kdf"/> as the KDF an ECDH derivation applies to the shared secret. It is judged from
    /// <c>CkmEcdh1DeriveParams</c>, which the ECDH entries' <see cref="MechanismChecks.Ecdh1DeriveParams"/> requires.
    /// </summary>
    /// <param name="kdf">The KDF.</param>
    /// <param name="rationale">Why it is allowed.</param>
    /// <exception cref="ArgumentException"><paramref name="kdf"/> is not a defined <see cref="CKD"/>, or <paramref name="rationale"/> is blank.</exception>
    public CryptoPolicyBuilder AllowKeyAgreementKdf(CKD kdf, string rationale)
    {
        if (!Enum.IsDefined(kdf))
            throw new ArgumentException($"{(ulong)kdf:X} is not a defined {nameof(CKD)}.", nameof(kdf));
        ArgumentException.ThrowIfNullOrWhiteSpace(rationale);
        _kdfs[kdf] = rationale;
        return this;
    }

    /// <summary>Removes <paramref name="kdf"/>, if allowed.</summary>
    /// <param name="kdf">The KDF to remove.</param>
    public CryptoPolicyBuilder RemoveKeyAgreementKdf(CKD kdf)
    {
        _kdfs.Remove(kdf);
        return this;
    }

    /// <summary>Allows key agreement with an existing key of <paramref name="keyType"/>.</summary>
    /// <param name="keyType">The key type.</param>
    /// <param name="rationale">Why it is allowed.</param>
    /// <exception cref="ArgumentException"><paramref name="rationale"/> is blank.</exception>
    public CryptoPolicyBuilder AllowKeyAgreementKeyType(CKK keyType, string rationale)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rationale);
        _keyAgreementKeyTypes[keyType] = rationale;
        return this;
    }

    /// <summary>Removes <paramref name="keyType"/>, if allowed.</summary>
    /// <param name="keyType">The key type to remove.</param>
    public CryptoPolicyBuilder RemoveKeyAgreementKeyType(CKK keyType)
    {
        _keyAgreementKeyTypes.Remove(keyType);
        return this;
    }

    /// <summary>
    /// Lets callers read one kind of secret key material off the token: the <c>…AndExportSecret</c> operations on
    /// <see cref="Pkcs11Key"/> and <see cref="Pkcs11Workspace"/>, and the byte-returning ECDH, ML-KEM and KDF adapters
    /// built on them. Every other kind stays refused, and every other rule keeps applying.
    /// </summary>
    /// <param name="kind">The kind of secret to allow reading.</param>
    /// <param name="rationale">Why reading it is needed.</param>
    /// <exception cref="ArgumentException"><paramref name="kind"/> is not a defined <see cref="SecretExportKind"/>,
    /// or <paramref name="rationale"/> is blank.</exception>
    public CryptoPolicyBuilder AllowSecretExport(SecretExportKind kind, string rationale)
    {
        if (!Enum.IsDefined(kind))
            throw new ArgumentException($"{(int)kind} is not a defined {nameof(SecretExportKind)}.", nameof(kind));
        ArgumentException.ThrowIfNullOrWhiteSpace(rationale);
        _secretExports[kind] = rationale;
        return this;
    }

    /// <summary>Refuses reading <paramref name="kind"/> again, if it was allowed.</summary>
    /// <param name="kind">The kind of secret to refuse.</param>
    public CryptoPolicyBuilder RemoveSecretExport(SecretExportKind kind)
    {
        _secretExports.Remove(kind);
        return this;
    }

    /// <summary>Replaces the RSA key-generation rule.</summary>
    /// <param name="rule">The rule.</param>
    public CryptoPolicyBuilder WithRsaKeyGenerationRule(RsaKeyGenerationRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        _rsaKeyGeneration = rule;
        return this;
    }

    /// <summary>Replaces the key-template rule.</summary>
    /// <param name="rule">The rule.</param>
    public CryptoPolicyBuilder WithKeyTemplateRule(KeyTemplateRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        _keyTemplate = rule;
        return this;
    }

    /// <summary>Replaces the secret export rule.</summary>
    /// <param name="rule">The rule.</param>
    public CryptoPolicyBuilder WithSecretExportRule(SecretExportRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        _secretExport = rule;
        return this;
    }

    /// <summary>Adds an allow-list entry as a whole (operations, legacy operations, check and rationale), widening as <see cref="Upsert"/> does.</summary>
    internal CryptoPolicyBuilder AllowRule(CKM mechanism, MechanismRule rule) =>
        Upsert(mechanism, rule.Operations, rule.LegacyOperations, rule.Rationale, rule.ParameterCheck);

    internal CryptoPolicyBuilder DocumentRefusedMechanism(CKM mechanism, DocumentedRefusal refusal) { _refusedMechanisms[mechanism] = refusal; return this; }
    internal CryptoPolicyBuilder DocumentRefusedHash(string name, DocumentedRefusal refusal) { _refusedHashes[name] = refusal; return this; }
    internal CryptoPolicyBuilder DocumentRefusedCurve(string oid, DocumentedRefusal refusal) { _refusedCurves[oid] = refusal; return this; }
    internal CryptoPolicyBuilder DocumentRefusedKdf(CKD kdf, DocumentedRefusal refusal) { _refusedKdfs[kdf] = refusal; return this; }
    internal CryptoPolicyBuilder DocumentRefusedKeyAgreementKeyType(CKK keyType, DocumentedRefusal refusal) { _refusedKeyAgreementKeyTypes[keyType] = refusal; return this; }
    internal CryptoPolicyBuilder DocumentRefusedPrf(string prf, DocumentedRefusal refusal) { _refusedPrfs[prf] = refusal; return this; }
    internal CryptoPolicyBuilder WithUnlistedMechanismHint(Func<PolicyIdentity, string>? hint) { _unlistedMechanismHint = hint; return this; }

    internal CryptoPolicyBuilder WithLegacyUseHint(string? hint) { _legacyUseHint = hint; return this; }

    // Not copied by CopyOf: a copy is the caller's own policy, not the built-in.
    internal CryptoPolicyBuilder WithBuiltInReference(string reference) { _builtInReference = reference; return this; }

    /// <summary>Marks a built-in for the docs generator; never copied by <see cref="ComposedCryptoPolicy.ToBuilder(string)"/>.</summary>
    internal CryptoPolicyBuilder WithDocumentation(PolicyDocumentation documentation) { _documentation = documentation; return this; }

    /// <summary>Builds the policy from the builder's current rules.</summary>
    public ComposedCryptoPolicy Build() => new(_name, _allowsOverride, new PolicyCatalogue
    {
        AllowedMechanisms = _mechanisms.ToFrozenDictionary(),
        AllowedVendorMechanisms = _vendorMechanisms.ToFrozenDictionary(),
        AllowedHashes = _hashes.ToFrozenDictionary(StringComparer.Ordinal),
        AllowedCurves = _curves.ToFrozenDictionary(StringComparer.Ordinal),
        AllowedKdfs = _kdfs.ToFrozenDictionary(),
        AllowedKeyAgreementKeyTypes = _keyAgreementKeyTypes.ToFrozenDictionary(),
        AllowedSecretExports = _secretExports.ToFrozenDictionary(),
        AllowedKdfPrfs = PolicyCatalogue.AllowedKdfPrfsFrom(_mechanisms.Values.Concat(_vendorMechanisms.Values)),
        RsaKeyGeneration = _rsaKeyGeneration,
        KeyTemplate = _keyTemplate,
        SecretExport = _secretExport,
        UnlistedMechanismHint = _unlistedMechanismHint,
        BuiltInReference = _builtInReference,
        LegacyUseHint = _legacyUseHint,
        Documentation = _documentation,
        DocumentedRefusedMechanisms = _refusedMechanisms.ToFrozenDictionary(),
        DocumentedRefusedHashes = _refusedHashes.ToFrozenDictionary(StringComparer.Ordinal),
        DocumentedRefusedCurves = _refusedCurves.ToFrozenDictionary(StringComparer.Ordinal),
        DocumentedRefusedKdfs = _refusedKdfs.ToFrozenDictionary(),
        DocumentedRefusedKeyAgreementKeyTypes = _refusedKeyAgreementKeyTypes.ToFrozenDictionary(),
        DocumentedRefusedPrfs = _refusedPrfs.ToFrozenDictionary(StringComparer.Ordinal),
    });

    private static string ValidateName(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        if (ReservedNames.Any(r => string.Equals(r, name.Trim(), StringComparison.OrdinalIgnoreCase)))
            throw new ArgumentException($"\"{name}\" is reserved for a built-in policy; choose your own name.", nameof(name));
        return name.Trim();
    }

    private static CryptoOperations ToFlags(IEnumerable<CryptoOperation> operations)
    {
        ArgumentNullException.ThrowIfNull(operations);
        CryptoOperations set = CryptoOperations.None;
        foreach (CryptoOperation op in operations)
        {
            if (!Enum.IsDefined(op))
                throw new ArgumentException($"{op} is not a defined {nameof(CryptoOperation)}.", nameof(operations));
            set |= (CryptoOperations)(1 << (int)op);
        }
        if (set == CryptoOperations.None)
            throw new ArgumentException("At least one operation is required.", nameof(operations));
        return set;
    }

    // HashUseRequest carries the BCL's names (HashAlgorithmName.SHA256 is "SHA256"), matched exactly; a known name in
    // another case is stored canonically so it matches instead of becoming a key no request ever uses.
    private static readonly string[] KnownHashNames =
    [
        HashAlgorithmName.MD5.Name!, HashAlgorithmName.SHA1.Name!, HashAlgorithmName.SHA256.Name!, HashAlgorithmName.SHA384.Name!,
        HashAlgorithmName.SHA512.Name!, HashAlgorithmName.SHA3_256.Name!, HashAlgorithmName.SHA3_384.Name!, HashAlgorithmName.SHA3_512.Name!,
    ];

    private static string HashName(HashAlgorithmName hash)
    {
        if (string.IsNullOrEmpty(hash.Name))
            throw new ArgumentException("The hash has no name.", nameof(hash));
        return KnownHashNames.FirstOrDefault(n => string.Equals(n, hash.Name, StringComparison.OrdinalIgnoreCase)) ?? hash.Name;
    }

    private static string CurveOid(Pkcs11ECCurve curve) =>
        curve.Oid ?? throw new ArgumentException("The curve has no OID.", nameof(curve));

    private static void Copy<TKey, TValue>(IReadOnlyDictionary<TKey, TValue> source, Dictionary<TKey, TValue> target) where TKey : notnull
    {
        foreach ((TKey key, TValue value) in source)
            target[key] = value;
    }
}
