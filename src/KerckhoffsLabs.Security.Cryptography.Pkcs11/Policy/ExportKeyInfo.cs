using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>
/// What the library read off the on-token key a secret is about to be read through: the base key of a KDF
/// (<see cref="KeyMaterialExportRequest.KdfBaseKey"/>), or the private key of a key agreement or KEM decapsulation
/// (<see cref="KeyMaterialExportRequest.PrivateKey"/>). The library reads it from the token before it asks the policy;
/// a policy only inspects it, and never makes token calls of its own.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Token"/> cannot be changed once the object exists. <see cref="AlwaysSensitive"/> and
/// <see cref="NeverExtractable"/> are set by the token alone and can never go from <see langword="false"/> back to
/// <see langword="true"/>, so a caller cannot change them either. An attribute the token does not report reads as
/// protected (<see langword="true"/>), so an unknown key is never mistaken for an unprotected or ephemeral one.
/// </para>
/// <para>
/// <see cref="Id"/> and <see cref="Label"/> are not security boundaries: anyone with a read/write session can change
/// them (<c>C_SetAttributeValue</c>) unless the object is <c>CKA_MODIFIABLE=false</c>. Use them to narrow a scope, not
/// to protect a key.
/// </para>
/// </remarks>
/// <param name="KeyType">The key's <c>CKA_KEY_TYPE</c>, or <see langword="null"/> when the token does not report it.</param>
/// <param name="Id">The key's <c>CKA_ID</c>; empty when it has none or the token does not report it.</param>
/// <param name="Label">The key's <c>CKA_LABEL</c>, or <see langword="null"/>.</param>
/// <param name="Token">
/// The key's <c>CKA_TOKEN</c>: <see langword="true"/> for a persistent token object, <see langword="false"/> for a session
/// object, which the token destroys when the session closes.
/// </param>
/// <param name="AlwaysSensitive">
/// The key's <c>CKA_ALWAYS_SENSITIVE</c>: <see langword="true"/> when its value has never been readable since the
/// token generated or derived it. <see langword="false"/> for a key imported from bytes (<c>C_CreateObject</c>), an
/// unwrapped key, and, per PKCS#11, a key derived from a base whose own value is <see langword="false"/>.
/// </param>
/// <param name="NeverExtractable">The key's <c>CKA_NEVER_EXTRACTABLE</c>.</param>
public sealed record ExportKeyInfo(
    CKK? KeyType, ReadOnlyMemory<byte> Id, string? Label, bool Token, bool AlwaysSensitive, bool NeverExtractable)
{
    /// <summary>A key whose attributes could not be read: as protected and as persistent as any.</summary>
    internal static ExportKeyInfo Unread { get; } =
        new(null, ReadOnlyMemory<byte>.Empty, null, Token: true, AlwaysSensitive: true, NeverExtractable: true);

    internal string Describe(string role) =>
        $"{(KeyType is { } type ? KeyTypeNames.Of(type) : "unknown-type")} {role}" +
        (Token ? " (token object" : " (session object") +
        (AlwaysSensitive ? ", always sensitive)" : ", not always sensitive)");
}
