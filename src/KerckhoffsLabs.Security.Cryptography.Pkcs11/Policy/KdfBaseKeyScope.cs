using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>
/// What the library read off the base key of a KDF whose output is about to leave the token
/// (<see cref="KeyMaterialExportRequest.KdfBaseKey"/>). The library reads it from the token before it asks the
/// policy; a policy only inspects it, and never makes token calls of its own.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="AlwaysSensitive"/> and <see cref="NeverExtractable"/> are set by the token alone and can never go from
/// <see langword="false"/> back to <see langword="true"/>, so a caller cannot change them. An attribute the token does
/// not report reads as <see langword="true"/>: as protected, so an unknown base key is never mistaken for an
/// unprotected one.
/// </para>
/// <para>
/// <see cref="Id"/> and <see cref="Label"/> are not security boundaries: anyone with a read/write session can change
/// them (<c>C_SetAttributeValue</c>) unless the object is <c>CKA_MODIFIABLE=false</c>. Use them to narrow a scope, not
/// to protect a key.
/// </para>
/// </remarks>
/// <param name="KeyType">The base key's <c>CKA_KEY_TYPE</c>, or <see langword="null"/> when the token does not report it.</param>
/// <param name="Id">The base key's <c>CKA_ID</c>; empty when it has none or the token does not report it.</param>
/// <param name="Label">The base key's <c>CKA_LABEL</c>, or <see langword="null"/>.</param>
/// <param name="AlwaysSensitive">
/// The base key's <c>CKA_ALWAYS_SENSITIVE</c>: <see langword="true"/> when its value has never been readable since the
/// token generated or derived it. <see langword="false"/> for a key imported from bytes (<c>C_CreateObject</c>), an
/// unwrapped key, and, per PKCS#11, a key derived from a base whose own value is <see langword="false"/>.
/// </param>
/// <param name="NeverExtractable">The base key's <c>CKA_NEVER_EXTRACTABLE</c>.</param>
public sealed record KdfBaseKeyInfo(
    CKK? KeyType, ReadOnlyMemory<byte> Id, string? Label, bool AlwaysSensitive, bool NeverExtractable)
{
    /// <summary>A base key whose attributes could not be read: as protected as any.</summary>
    internal static KdfBaseKeyInfo Unread { get; } = new(null, ReadOnlyMemory<byte>.Empty, null, AlwaysSensitive: true, NeverExtractable: true);

    internal string Describe() =>
        $"{(KeyType is { } type ? KeyTypeNames.Of(type) : "unknown-type")} base key" +
        (AlwaysSensitive ? " (always sensitive)" : " (not always sensitive)");
}

/// <summary>
/// The base keys a <see cref="KeyMaterialExportKind.KdfOutput"/> opt-in covers
/// (<see cref="KeyMaterialExportRule.Allow(IEnumerable{KeyMaterialExportKind}, string, KdfBaseKeyScope)"/>).
/// </summary>
/// <remarks>
/// <para>
/// KDF output is the value of a key the token could derive from the same base with the same mechanism. Reading it
/// over a base key the token has always protected reproduces keys that were meant never to leave it: every sensitive
/// key derived from the agreed secret of <c>Pkcs11Key.DeriveSecretAgreement</c>, or from an on-token master key. The
/// scope says which base keys that is acceptable for.
/// </para>
/// <para>
/// <see cref="NeverProtected"/> is the default, and covers the byte-returning BCL adapters' usual inputs: key material
/// the application imported, and keys derived on the token from it. <see cref="KdfBaseKeyInfo.AlwaysSensitive"/>-based scoping relies
/// on the token keeping <c>CKA_ALWAYS_SENSITIVE</c> as PKCS#11 requires; a token that clears it on derived keys makes
/// <see cref="NeverProtected"/> admit them. Unwrapped keys are never <c>CKA_ALWAYS_SENSITIVE</c>, whatever their
/// history, so a key provisioned under a KEK is admitted too. Keep such keys out of sessions whose policy allows
/// <see cref="KeyMaterialExportKind.KdfOutput"/>, or narrow the scope further with <see cref="Where"/>.
/// </para>
/// <para>A KDF with no base key (PBKDF2, whose input is a password the caller holds) is in every scope.</para>
/// </remarks>
public sealed class KdfBaseKeyScope
{
    private readonly Func<KdfBaseKeyInfo, bool> _admits;

    private KdfBaseKeyScope(Func<KdfBaseKeyInfo, bool> admits, string description)
    {
        _admits = admits;
        Description = description;
    }

    /// <summary>
    /// Base keys whose value the token has not always protected (<c>CKA_ALWAYS_SENSITIVE</c> is <see langword="false"/>):
    /// key material the application imported and keys derived from it. The default scope.
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
    /// <see cref="KdfBaseKeyInfo.AlwaysSensitive"/> yourself to keep the default's protection.
    /// </summary>
    /// <param name="predicate">Decides from what the library read off the base key; must not throw or call the token.</param>
    /// <param name="description">What the scope admits, for the policy catalogue; must not be blank.</param>
    /// <exception cref="ArgumentNullException"><paramref name="predicate"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="description"/> is blank.</exception>
    public static KdfBaseKeyScope Where(Func<KdfBaseKeyInfo, bool> predicate, string description)
    {
        ArgumentNullException.ThrowIfNull(predicate);
        ArgumentException.ThrowIfNullOrWhiteSpace(description);
        return new(predicate, description.Trim());
    }

    /// <summary>What the scope admits, in a few words.</summary>
    public string Description { get; }

    /// <summary>Whether KDF output over <paramref name="baseKey"/> is in scope; a KDF with no base key always is.</summary>
    internal bool Admits(KdfBaseKeyInfo? baseKey) => baseKey is null || _admits(baseKey);
}
