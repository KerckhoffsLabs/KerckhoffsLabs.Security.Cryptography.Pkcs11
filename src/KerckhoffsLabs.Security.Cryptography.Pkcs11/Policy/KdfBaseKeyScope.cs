namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>
/// The base keys a <see cref="KeyMaterialExportKind.KdfOutput"/> opt-in covers: the <c>kdfBaseKeys</c> argument of
/// <see cref="KeyMaterialExportRule.Allow"/>, which an opt-in to <see cref="KeyMaterialExportKind.KdfOutput"/> must name.
/// </summary>
/// <remarks>
/// <para>
/// KDF output is the value of a key the token could derive from the same base with the same mechanism. Reading it
/// over a base key the token has always protected reproduces keys that were meant never to leave it: every sensitive
/// key derived from the agreed secret of <c>Pkcs11Key.DeriveSecretAgreement</c>, or from an on-token master key. The
/// scope says which base keys that is acceptable for.
/// </para>
/// <para>
/// There is no default: every scope here relies on something the caller should weigh. <see cref="NeverProtected"/>
/// covers the byte-returning BCL adapters' usual inputs (key material the application imported, and keys derived on
/// the token from it), but it relies on the token keeping <c>CKA_ALWAYS_SENSITIVE</c> as PKCS#11 requires: a token
/// that clears it on derived keys makes <see cref="NeverProtected"/> admit them. Unwrapped keys are never
/// <c>CKA_ALWAYS_SENSITIVE</c>, whatever their history, so a key provisioned under a KEK is admitted too. Keep such
/// keys out of sessions whose policy allows <see cref="KeyMaterialExportKind.KdfOutput"/>, or narrow the scope further
/// with <see cref="Where"/>.
/// </para>
/// <para>A KDF with no base key (PBKDF2, whose input is a password the caller holds) is in every scope.</para>
/// </remarks>
public sealed class KdfBaseKeyScope
{
    private readonly Func<ExportKeyInfo, bool> _admits;

    private KdfBaseKeyScope(Func<ExportKeyInfo, bool> admits, string description)
    {
        _admits = admits;
        Description = description;
    }

    /// <summary>
    /// Base keys whose value the token has not always protected (<c>CKA_ALWAYS_SENSITIVE</c> is <see langword="false"/>):
    /// key material the application imported and keys derived from it. See the remarks for what it relies on.
    /// </summary>
    public static KdfBaseKeyScope NeverProtected { get; } = new(
        k => !k.AlwaysSensitive, "base keys that are not CKA_ALWAYS_SENSITIVE");

    /// <summary>
    /// Every base key the session can use, including ones the token has always protected. KDF output over such a key
    /// reproduces every key derived from it with the same mechanism; name this only when that is the point.
    /// </summary>
    public static KdfBaseKeyScope Any { get; } = new(_ => true, "any base key");

    /// <summary>
    /// The base keys <paramref name="predicate"/> admits. It decides alone: combine it with
    /// <see cref="ExportKeyInfo.AlwaysSensitive"/> yourself to keep <see cref="NeverProtected"/>'s protection.
    /// </summary>
    /// <param name="predicate">Decides from what the library read off the base key; must not throw or call the token.</param>
    /// <param name="description">What the scope admits, for the policy catalogue; must not be blank.</param>
    /// <exception cref="ArgumentNullException"><paramref name="predicate"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="description"/> is blank.</exception>
    public static KdfBaseKeyScope Where(Func<ExportKeyInfo, bool> predicate, string description)
    {
        ArgumentNullException.ThrowIfNull(predicate);
        ArgumentException.ThrowIfNullOrWhiteSpace(description);
        return new(predicate, description.Trim());
    }

    /// <summary>What the scope admits, in a few words.</summary>
    public string Description { get; }

    /// <summary>Whether KDF output over <paramref name="baseKey"/> is in scope; a KDF with no base key always is.</summary>
    internal bool Admits(ExportKeyInfo? baseKey) => baseKey is null || _admits(baseKey);
}
