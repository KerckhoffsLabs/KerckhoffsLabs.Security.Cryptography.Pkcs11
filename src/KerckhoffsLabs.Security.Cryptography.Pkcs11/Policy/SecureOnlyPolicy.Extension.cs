using System.Collections.Frozen;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;
using S = KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.CryptoOperations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

// The extension points: WithAllowedMechanism, and the narrow opt-ins for the rules that are not
// about a mechanism (key-material export, EC curves, key-agreement KDFs).
public sealed partial class SecureOnlyPolicy
{
    /// <summary>The name every instance returned by one of the <c>WithAllowed*</c> methods carries.</summary>
    private const string ExtendedName = "SecureOnly+custom";

    /// <summary>
    /// Returns a new <see cref="SecureOnlyPolicy"/> — named <c>"SecureOnly+custom"</c> — that also allows
    /// <paramref name="mechanism"/> for the given <paramref name="operations"/>, on top of everything this
    /// instance already allows. It adds to, and never removes from, what this instance allows. This
    /// instance, and <see cref="CryptoPolicy.SecureOnly"/> itself, are unaffected: call it again to layer
    /// on another mechanism, or reassign a variable to keep using the wider policy.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This widens what SecureOnly permits.</b> It is the reviewed escape hatch for a mechanism this
    /// library has not put on the SecureOnly allow-list — including one on its documented deny list (see
    /// the remarks on <see cref="SecureOnlyPolicy"/>), which only documents a reason and an alternative and
    /// never itself enforces a denial. Call it only after <em>you</em> have reviewed the mechanism, its
    /// parameters, and the operations you are approving for your specific use case.
    /// </para>
    /// <para>
    /// If <paramref name="mechanism"/> already has an entry — built in, or added by an earlier call — it
    /// is widened, never replaced: <paramref name="operations"/> is added to the operations it already
    /// allows, and its parameter check, if any, is kept and applies to the new operations too (for
    /// example <c>CKM_RSA_PKCS_OAEP</c> still requires <c>CkmRsaPkcsOaepParams</c> naming an allowed
    /// hash). A built-in entry keeps its rationale, followed by <c>"Extended: "</c> and
    /// <paramref name="reason"/>; an entry added by an earlier call takes <paramref name="reason"/> as its
    /// rationale (the latest reason wins). A new entry allows exactly <paramref name="operations"/>, with
    /// no parameter check and <paramref name="reason"/> as its rationale. The rationale appears in the
    /// generated catalogue documentation for this instance, alongside the built-in entries.
    /// </para>
    /// <para>
    /// There is no equivalent on <c>FipsOnly</c>: its allow-list is a closed, NIST-approved set and cannot
    /// be widened by a caller.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Decrypting a vendor's legacy DES-CBC archive: reviewed, decrypt-only, never used to encrypt.
    /// ICryptoPolicy reviewed = CryptoPolicy.SecureOnly.WithAllowedMechanism(
    ///     CKM.CKM_DES_CBC,
    ///     [CryptoOperation.Decrypt],
    ///     "Legacy archive decryption only; verified offline that no code path re-encrypts under DES.");
    /// </code>
    /// </example>
    /// <param name="mechanism">
    /// The mechanism to allow. A vendor mechanism is passed as its value cast to <see cref="CKM"/>, and
    /// lands in the vendor allow-list (<c>≥ CKM_VENDOR_DEFINED</c>, the split
    /// <see cref="Mechanism.IsVendorDefined"/> uses).
    /// </param>
    /// <param name="operations">The operations to approve <paramref name="mechanism"/> for. Must not be empty.</param>
    /// <param name="reason">
    /// Why <paramref name="mechanism"/> is approved for your use case. Recorded as the new entry's
    /// rationale and shown in the generated documentation for the returned instance.
    /// </param>
    /// <returns>A new, wider <see cref="SecureOnlyPolicy"/> named <c>"SecureOnly+custom"</c>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="operations"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="operations"/> is empty or contains a value that is not a defined
    /// <see cref="CryptoOperation"/>, or <paramref name="reason"/> is <see langword="null"/>, empty, or whitespace.
    /// </exception>
    public SecureOnlyPolicy WithAllowedMechanism(CKM mechanism, IEnumerable<CryptoOperation> operations, string reason)
    {
        ArgumentNullException.ThrowIfNull(operations);
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        S ops = S.None;
        foreach (CryptoOperation op in operations)
        {
            if (!Enum.IsDefined(op))
                throw new ArgumentException($"{(int)op} is not a defined {nameof(CryptoOperation)}.", nameof(operations));
            ops |= (S)(1 << (int)op);
        }
        if (ops == S.None)
            throw new ArgumentException("At least one operation must be approved.", nameof(operations));

        PolicyCatalogue extendedCatalogue = WithMechanismEntry((ulong)mechanism, ops, reason);
        return new SecureOnlyPolicy(extendedCatalogue, ExtendedName);
    }

    /// <summary>
    /// Builds a copy of <see cref="_catalogue"/> with one mechanism entry added or widened, routed to
    /// <see cref="PolicyCatalogue.AllowedMechanisms"/> or <see cref="PolicyCatalogue.AllowedVendorMechanisms"/>
    /// by <paramref name="raw"/>'s value against <see cref="CKM.CKM_VENDOR_DEFINED"/>, the same test
    /// <see cref="Mechanism.IsVendorDefined"/> uses.
    /// </summary>
    private PolicyCatalogue WithMechanismEntry(ulong raw, S operations, string reason)
    {
        FrozenDictionary<CKM, MechanismRule> allowedMechanisms = _catalogue.AllowedMechanisms;
        FrozenDictionary<ulong, MechanismRule> allowedVendorMechanisms = _catalogue.AllowedVendorMechanisms;

        if (raw >= (ulong)CKM.CKM_VENDOR_DEFINED)
        {
            var updated = new Dictionary<ulong, MechanismRule>(allowedVendorMechanisms)
            {
                [raw] = ExtendedEntry(allowedVendorMechanisms.GetValueOrDefault(raw), builtIn: null, operations, reason),
            };
            allowedVendorMechanisms = updated.ToFrozenDictionary();
        }
        else
        {
            var standard = (CKM)raw;
            var updated = new Dictionary<CKM, MechanismRule>(allowedMechanisms)
            {
                [standard] = ExtendedEntry(
                    allowedMechanisms.GetValueOrDefault(standard),
                    DefaultCatalogue.AllowedMechanisms.GetValueOrDefault(standard),
                    operations,
                    reason),
            };
            allowedMechanisms = updated.ToFrozenDictionary();
        }

        return CopyCatalogue(allowedMechanisms: allowedMechanisms, allowedVendorMechanisms: allowedVendorMechanisms);
    }

    /// <summary>
    /// The entry <see cref="WithMechanismEntry"/> installs. Never narrows: an <paramref name="existing"/>
    /// entry keeps its operations, legacy operations and parameter check, and gains
    /// <paramref name="operations"/>. The rationale is the <paramref name="builtIn"/> entry's (the default
    /// SecureOnly catalogue's entry for the same mechanism, if any) followed by <c>"Extended: "</c> and
    /// <paramref name="reason"/>, or just <paramref name="reason"/> for a mechanism with no built-in entry.
    /// </summary>
    private static MechanismRule ExtendedEntry(MechanismRule? existing, MechanismRule? builtIn, S operations, string reason)
    {
        string rationale = builtIn is null ? reason : $"{builtIn.Rationale} Extended: {reason}";
        return existing is null
            ? new MechanismRule(operations, S.None, null, rationale)
            : existing with { Operations = existing.Operations | operations, Rationale = rationale };
    }

    // --- Narrow opt-ins for the rules that are not about a mechanism ---

    /// <summary>
    /// Returns a new <see cref="SecureOnlyPolicy"/> — named <c>"SecureOnly+custom"</c> — that also allows
    /// key material of <paramref name="kind"/> to be read off the token, on top of everything this
    /// instance already allows. This instance, and <see cref="CryptoPolicy.SecureOnly"/> itself, are
    /// unaffected.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This widens what SecureOnly permits</b>, but only for the one kind of export named: every other
    /// kind is still refused, and every other SecureOnly rule — mechanisms, hashes, curves, KDFs, key
    /// templates — still applies. Exports happen only through the read-back operations
    /// (<see cref="Pkcs11Key.DeriveAndExportSecret"/>, <see cref="Pkcs11Key.EncapsulateAndExportSecret"/>,
    /// <see cref="Pkcs11Key.DecapsulateAndExportSecret"/>, <see cref="Pkcs11Workspace.DeriveAndExportSecret"/>),
    /// which accept a closed list of mechanisms and create, read and destroy their own ephemeral key: that
    /// key is not refused as a key template, and for a raw ECDH secret the <c>CKD_NULL</c> derivation is
    /// not refused as a key-agreement KDF. A non-sensitive key created any other way is still refused.
    /// Prefer this to <see cref="CryptoPolicy.AllowInsecure"/>, which switches all of them off. The
    /// adapters that hand secret bytes to managed code are built on those operations and need it:
    /// <see cref="KeyMaterialExportKind.EcdhSharedSecret"/> for <c>ECDiffieHellmanPkcs11.DeriveKey*</c>,
    /// <see cref="KeyMaterialExportKind.KemSharedSecret"/> for <c>MLKemPkcs11</c>,
    /// <see cref="KeyMaterialExportKind.KdfOutput"/> for the byte-returning HKDF and SP 800-108
    /// adapters, and <see cref="KeyMaterialExportKind.PasswordKdfOutput"/> for the PBKDF2 one. The
    /// alternative that needs no opt-in is to keep the secret on the token — derive or decapsulate to a
    /// sensitive <see cref="Pkcs11Key"/>.
    /// </para>
    /// <para>
    /// <paramref name="reason"/> is appended to the key-material export rationale shown in the generated
    /// catalogue documentation for the returned instance. There is no equivalent on <c>FipsOnly</c>.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// SecureOnlyPolicy reviewed = CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport(
    ///     KeyMaterialExportKind.EcdhSharedSecret,
    ///     "The shared secret feeds our protocol's own KDF in managed code; reviewed with the protocol owners.");
    /// </code>
    /// </example>
    /// <param name="kind">The kind of key material to allow reading off the token.</param>
    /// <param name="reason">Why the export is approved for your use case. Recorded in the generated documentation.</param>
    /// <returns>A new, wider <see cref="SecureOnlyPolicy"/> named <c>"SecureOnly+custom"</c>.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="kind"/> is not a defined <see cref="KeyMaterialExportKind"/>, or
    /// <paramref name="reason"/> is <see langword="null"/>, empty, or whitespace.
    /// </exception>
    public SecureOnlyPolicy WithAllowedKeyMaterialExport(KeyMaterialExportKind kind, string reason)
    {
        if (!Enum.IsDefined(kind))
            throw new ArgumentException($"{(int)kind} is not a defined {nameof(KeyMaterialExportKind)}.", nameof(kind));
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        PolicyRules rules = _catalogue.Rules;
        Func<KeyMaterialExportRequest, PolicyDecision> previous = rules.KeyMaterialExport;
        PolicyRules widened = rules with
        {
            KeyMaterialExport = r => r.Kind == kind ? PolicyDecision.Allow : previous(r),
            KeyMaterialExportRationale = $"{rules.KeyMaterialExportRationale} Allowed: {kind} — {reason}",
        };
        return new SecureOnlyPolicy(CopyCatalogue(rules: widened), ExtendedName);
    }

    /// <summary>
    /// Returns a new <see cref="SecureOnlyPolicy"/> — named <c>"SecureOnly+custom"</c> — that also allows
    /// generating EC keys on <paramref name="curve"/>, on top of everything this instance already allows.
    /// This instance, and <see cref="CryptoPolicy.SecureOnly"/> itself, are unaffected.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This widens what SecureOnly permits</b>, but only for the one curve named — typically a curve
    /// below 128-bit security that an existing protocol or peer still requires. Every other SecureOnly
    /// rule still applies. Prefer it to <see cref="CryptoPolicy.AllowInsecure"/>, which switches all of
    /// them off.
    /// </para>
    /// <para>
    /// A curve that is already allowed keeps its entry, and <paramref name="reason"/> is appended to its
    /// rationale. The rationale appears in the generated catalogue documentation for the returned
    /// instance. There is no equivalent on <c>FipsOnly</c>.
    /// </para>
    /// </remarks>
    /// <param name="curve">The named curve to allow.</param>
    /// <param name="reason">Why the curve is approved for your use case. Recorded in the generated documentation.</param>
    /// <returns>A new, wider <see cref="SecureOnlyPolicy"/> named <c>"SecureOnly+custom"</c>.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="curve"/> is the default (unnamed) curve, or <paramref name="reason"/> is
    /// <see langword="null"/>, empty, or whitespace.
    /// </exception>
    public SecureOnlyPolicy WithAllowedCurve(Pkcs11ECCurve curve, string reason)
    {
        string oid = curve.Oid ?? throw new ArgumentException("The curve must be a named curve.", nameof(curve));
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        FrozenDictionary<string, string> curves = _catalogue.AllowedCurves;
        var updated = new Dictionary<string, string>(curves, StringComparer.Ordinal)
        {
            [oid] = curves.TryGetValue(oid, out string? existing) ? $"{existing} Extended: {reason}" : reason,
        };
        return new SecureOnlyPolicy(
            CopyCatalogue(allowedCurves: updated.ToFrozenDictionary(StringComparer.Ordinal)), ExtendedName);
    }

    /// <summary>
    /// Returns a new <see cref="SecureOnlyPolicy"/> — named <c>"SecureOnly+custom"</c> — that also allows
    /// <paramref name="kdf"/> as the key-derivation function of an ECDH key agreement, on top of
    /// everything this instance already allows. This instance, and <see cref="CryptoPolicy.SecureOnly"/>
    /// itself, are unaffected.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This widens what SecureOnly permits</b>, but only for the one KDF named — for example
    /// <see cref="CKD.CKD_NULL"/> for a token such as SoftHSM2 that only implements the raw shared secret.
    /// Every other SecureOnly rule still applies. Prefer it to <see cref="CryptoPolicy.AllowInsecure"/>,
    /// which switches all of them off.
    /// </para>
    /// <para>
    /// A KDF that is already allowed keeps its entry, and <paramref name="reason"/> is appended to its
    /// rationale. The rationale appears in the generated catalogue documentation for the returned
    /// instance. There is no equivalent on <c>FipsOnly</c>.
    /// </para>
    /// </remarks>
    /// <param name="kdf">The key-derivation function to allow.</param>
    /// <param name="reason">Why the KDF is approved for your use case. Recorded in the generated documentation.</param>
    /// <returns>A new, wider <see cref="SecureOnlyPolicy"/> named <c>"SecureOnly+custom"</c>.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="kdf"/> is not a defined <see cref="CKD"/>, or <paramref name="reason"/> is
    /// <see langword="null"/>, empty, or whitespace.
    /// </exception>
    public SecureOnlyPolicy WithAllowedKeyAgreementKdf(CKD kdf, string reason)
    {
        if (!Enum.IsDefined(kdf))
            throw new ArgumentException($"{(ulong)kdf} is not a defined {nameof(CKD)}.", nameof(kdf));
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        FrozenDictionary<CKD, string> kdfs = _catalogue.AllowedKdfs;
        var updated = new Dictionary<CKD, string>(kdfs)
        {
            [kdf] = kdfs.TryGetValue(kdf, out string? existing) ? $"{existing} Extended: {reason}" : reason,
        };
        return new SecureOnlyPolicy(CopyCatalogue(allowedKdfs: updated.ToFrozenDictionary()), ExtendedName);
    }

    /// <summary>A copy of <see cref="_catalogue"/> with the given members replaced and everything else kept.</summary>
    private PolicyCatalogue CopyCatalogue(
        FrozenDictionary<CKM, MechanismRule>? allowedMechanisms = null,
        FrozenDictionary<ulong, MechanismRule>? allowedVendorMechanisms = null,
        FrozenDictionary<string, string>? allowedCurves = null,
        FrozenDictionary<CKD, string>? allowedKdfs = null,
        PolicyRules? rules = null) => new()
        {
            AllowedMechanisms = allowedMechanisms ?? _catalogue.AllowedMechanisms,
            AllowedVendorMechanisms = allowedVendorMechanisms ?? _catalogue.AllowedVendorMechanisms,
            AllowedHashes = _catalogue.AllowedHashes,
            AllowedCurves = allowedCurves ?? _catalogue.AllowedCurves,
            AllowedKdfs = allowedKdfs ?? _catalogue.AllowedKdfs,
            AllowedKeyAgreementKeyTypes = _catalogue.AllowedKeyAgreementKeyTypes,
            AllowedKdfPrfs = _catalogue.AllowedKdfPrfs,
            Rules = rules ?? _catalogue.Rules,
            DocumentedRefusedMechanisms = _catalogue.DocumentedRefusedMechanisms,
            DocumentedRefusedHashes = _catalogue.DocumentedRefusedHashes,
            DocumentedRefusedCurves = _catalogue.DocumentedRefusedCurves,
            DocumentedRefusedKdfs = _catalogue.DocumentedRefusedKdfs,
            DocumentedRefusedKeyAgreementKeyTypes = _catalogue.DocumentedRefusedKeyAgreementKeyTypes,
            DocumentedRefusedPrfs = _catalogue.DocumentedRefusedPrfs,
        };
}
