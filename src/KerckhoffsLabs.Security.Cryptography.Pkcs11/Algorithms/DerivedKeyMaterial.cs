using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// Reads the output of an on-token KDF back into managed memory, for the adapters whose BCL contract
/// returns bytes (<see cref="SP800108HmacCounterKdfPkcs11"/>, <see cref="HkdfPkcs11"/>,
/// <see cref="Pkcs11Key.DeriveBytes"/>).
/// </summary>
internal static class DerivedKeyMaterial
{
    /// <summary>
    /// Derives an ephemeral, extractable generic secret of <paramref name="length"/> bytes from
    /// <paramref name="baseKey"/>, reads its value and destroys it.
    /// </summary>
    /// <exception cref="CryptoPolicyViolationException">The session's policy refuses reading KDF output off the token.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_DeriveKey</c> or <c>C_GetAttributeValue</c>.</exception>
    /// <exception cref="InvalidOperationException">The token did not expose the derived value.</exception>
    /// <exception cref="CryptographicException">The token returned a value of a different length than requested.</exception>
    public static byte[] DeriveAndRead(Pkcs11Key baseKey, Mechanism mechanism, int length)
    {
        // The export check comes first: it is what a policy that allows extractable templates but not
        // plaintext KDF output (a FIPS-style policy) relies on.
        // The base key is judged too: KDF output over a key the token has always protected would reproduce every
        // key derived from it (KdfBaseKeyScope).
        using SecretReadBack readBack = baseKey.Session.BeginReadBack(KeyMaterialExportKind.KdfOutput, baseKey);
        using var template = ExtractableSecretTemplate(length);
        return readBack.Read(() => baseKey.Derive(mechanism, template), length, ReadBackFailures.KdfOutput);
    }

    /// <summary>
    /// A session-scoped, extractable, non-sensitive generic secret of <paramref name="length"/> bytes, so its
    /// <c>CKA_VALUE</c> can be read back. Created inside a <see cref="SecretReadBack"/>, the policy judges it as that
    /// read-back (<see cref="KeyTemplateRequest.ReadBackFor"/>).
    /// </summary>
    internal static ObjectTemplate ExtractableSecretTemplate(int length) =>
        ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .ValueLen(length)
            .Extractable()
            .Sensitive(false)
            .Build();
}
