using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>A policy's rule for reading derived or agreed secret material off the token in the clear.</summary>
public sealed class SecretExportRule
{
    private readonly Func<SecretExportRequest, PolicyIdentity, PolicyDecision> _evaluate;

    private SecretExportRule(Func<SecretExportRequest, PolicyIdentity, PolicyDecision> evaluate, string rationale)
    {
        _evaluate = evaluate;
        Rationale = rationale;
    }

    /// <summary>
    /// Refuses every read of secret key material off the token. The refusal names the on-token operation that
    /// avoids the export, and the narrow opt-in (<see cref="CryptoPolicyBuilder.AllowSecretExport"/>) on
    /// the refusing policy's builder.
    /// </summary>
    public static SecretExportRule Refuse() => Refuse(
        "Reading secret key material off the token in the clear is refused; wrap it under a KEK instead.",
        (kind, policy) => $"Reading the {kind} off the token violates the non-extractable-by-default posture. " +
                              $"Keep the secret on the token instead: {OnTokenAlternative(kind)}. If the export is needed, " +
                              $"allow this one kind with {policy.WideningCall($"AllowSecretExport(SecretExportKind.{kind}, reason)")}.");

    /// <summary>The on-token operation that keeps a secret of <paramref name="kind"/> on the token instead.</summary>
    internal static string OnTokenAlternative(SecretExportKind kind) => kind switch
    {
        SecretExportKind.EcdhSharedSecret =>
            "Pkcs11Workspace.DeriveSharedSecretEcdh applies the KDF on the token and returns a sensitive key",
        SecretExportKind.KemSharedSecret =>
            "Pkcs11Key.EncapsulateKey / DecapsulateKey return the shared secret as a sensitive key",
        SecretExportKind.KdfOutput =>
            "Pkcs11Key.Derive with a sensitive template, or the ObjectTemplate overloads of HkdfPkcs11 " +
            "(DeriveKey / ExtractKey / ExpandKey) and SP800108HmacCounterKdfPkcs11.DeriveKey, derive a sensitive key",
        SecretExportKind.PasswordKdfOutput =>
            "Pkcs11Workspace.GenerateKey with CKM_PKCS5_PBKD2, or Rfc2898DeriveBytesPkcs11.Pbkdf2Key, derives a sensitive key",
        _ => "derive a sensitive key with Pkcs11Key.Derive",
    };

    /// <param name="rationale">The rule's catalogue rationale.</param>
    /// <param name="denial">The refusal, from the kind and the identity of the policy that refused.</param>
    internal static SecretExportRule Refuse(string rationale, Func<SecretExportKind, PolicyIdentity, string> denial) =>
        new((r, policy) => PolicyDecision.Deny(denial(r.Kind, policy)), rationale);

    /// <summary>A rule backed by a delegate. Test seam: production policies use the public factories.</summary>
    internal static SecretExportRule FromDelegate(Func<SecretExportRequest, PolicyDecision> evaluate, string rationale) =>
        new((r, _) => evaluate(r), rationale);

    internal string Rationale { get; }

    internal PolicyDecision Evaluate(SecretExportRequest request, PolicyIdentity policy) => _evaluate(request, policy);
}
