using System.Collections.Frozen;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;
using S = KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.CryptoOperations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

// The extension point: SecureOnlyPolicy.WithAllowedMechanism.
public sealed partial class SecureOnlyPolicy
{
    /// <summary>The name every instance returned by <see cref="WithAllowedMechanism(CKM, IEnumerable{CryptoOperation}, string)"/> carries.</summary>
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
    /// <param name="mechanism">The standard mechanism to allow.</param>
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
        => WithAllowedMechanism((ulong)mechanism, operations, reason);

    /// <summary>
    /// Vendor-mechanism overload of <see cref="WithAllowedMechanism(CKM, IEnumerable{CryptoOperation}, string)"/> —
    /// see its remarks for what is allowed, how an existing entry is widened, and validation.
    /// </summary>
    /// <remarks>
    /// Both overloads route by the raw <c>CK_MECHANISM_TYPE</c> value, not by which overload was called: a
    /// value below <c>CKM_VENDOR_DEFINED</c> always lands in the standard allow-list and a value at or
    /// above it — including one wider than 32 bits, where <c>CK_ULONG</c> is 64-bit — always lands in the
    /// vendor allow-list, the same split <see cref="Mechanism.IsVendorDefined"/> uses. Passing a standard
    /// mechanism's value through this overload, or a vendor value cast to <see cref="CKM"/> through the
    /// other, behaves identically to using the matching overload directly.
    /// </remarks>
    /// <param name="vendorMechanism">The mechanism's raw <c>CK_MECHANISM_TYPE</c> value.</param>
    /// <param name="operations">The operations to approve the mechanism for. Must not be empty.</param>
    /// <param name="reason">
    /// Why the mechanism is approved for your use case. Recorded as the new entry's rationale and shown
    /// in the generated documentation for the returned instance.
    /// </param>
    /// <returns>A new, wider <see cref="SecureOnlyPolicy"/> named <c>"SecureOnly+custom"</c>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="operations"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="operations"/> is empty or contains a value that is not a defined
    /// <see cref="CryptoOperation"/>, or <paramref name="reason"/> is <see langword="null"/>, empty, or whitespace.
    /// </exception>
    public SecureOnlyPolicy WithAllowedMechanism(ulong vendorMechanism, IEnumerable<CryptoOperation> operations, string reason)
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

        PolicyCatalogue extendedCatalogue = WithMechanismEntry(vendorMechanism, ops, reason);
        return new SecureOnlyPolicy(extendedCatalogue, ExtendedName);
    }

    /// <summary>
    /// Builds a copy of <see cref="_catalogue"/> with one mechanism entry added or widened, routed to
    /// <see cref="PolicyCatalogue.AllowedMechanisms"/> or <see cref="PolicyCatalogue.AllowedVendorMechanisms"/>
    /// by <paramref name="raw"/>'s value against <see cref="CKM.CKM_VENDOR_DEFINED"/>, the same test
    /// <see cref="Mechanism.IsVendorDefined"/> uses. A value wider than 32 bits is vendor-range and is never
    /// cast to <see cref="CKM"/>.
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

        return new PolicyCatalogue
        {
            AllowedMechanisms = allowedMechanisms,
            AllowedVendorMechanisms = allowedVendorMechanisms,
            AllowedHashes = _catalogue.AllowedHashes,
            AllowedCurves = _catalogue.AllowedCurves,
            AllowedKdfs = _catalogue.AllowedKdfs,
            AllowedKeyAgreementKeyTypes = _catalogue.AllowedKeyAgreementKeyTypes,
            AllowedKdfPrfs = _catalogue.AllowedKdfPrfs,
            Rules = _catalogue.Rules,
            DocumentedRefusedMechanisms = _catalogue.DocumentedRefusedMechanisms,
            DocumentedRefusedHashes = _catalogue.DocumentedRefusedHashes,
            DocumentedRefusedCurves = _catalogue.DocumentedRefusedCurves,
            DocumentedRefusedKdfs = _catalogue.DocumentedRefusedKdfs,
            DocumentedRefusedKeyAgreementKeyTypes = _catalogue.DocumentedRefusedKeyAgreementKeyTypes,
            DocumentedRefusedPrfs = _catalogue.DocumentedRefusedPrfs,
        };
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
}
