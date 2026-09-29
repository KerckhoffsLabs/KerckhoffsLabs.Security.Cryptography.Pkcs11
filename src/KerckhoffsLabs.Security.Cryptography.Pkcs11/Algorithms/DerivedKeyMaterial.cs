using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// Reads the output of an on-token KDF back into managed memory, for the adapters whose BCL contract
/// returns bytes (<see cref="SP800108HmacCounterKdfPkcs11"/>, <see cref="HkdfPkcs11"/>).
/// </summary>
internal static class DerivedKeyMaterial
{
    /// <summary>
    /// Derives an ephemeral, extractable generic secret of <paramref name="length"/> bytes from
    /// <paramref name="baseKey"/>, reads its value and destroys it.
    /// </summary>
    /// <exception cref="CryptoPolicyViolationException">The workspace's policy refuses reading KDF output off the token.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_DeriveKey</c> or <c>C_GetAttributeValue</c>.</exception>
    /// <exception cref="InvalidOperationException">The token did not expose the derived value.</exception>
    public static byte[] DeriveAndRead(Pkcs11Key baseKey, Mechanism mechanism, int length)
    {
        baseKey.Workspace.Enforce(new KeyMaterialExportRequest(KeyMaterialExportKind.KdfOutput));

        // Session-scoped, extractable, non-sensitive generic secret so CKA_VALUE can be read back.
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .ValueLen(length)
            .Extractable()
            .Sensitive(false)
            .Build();

        // Public, gated path — the same one an external caller would use. The template asks for an
        // extractable, non-sensitive key, so the policy also judges it as a key template; the export
        // check above is what a policy that allows such templates but not plaintext KDF output
        // (a FIPS-style policy) relies on.
        Pkcs11Key derived = baseKey.Derive(mechanism, template);
        bool operationFailed = true;
        try
        {
            // ObjectAttribute owns an unmanaged buffer holding the derived key material, and
            // freeing it is what zeroizes it. Without this the secret stays in unmanaged memory
            // for the life of the process.
            using var attrs = derived.GetAttributeValue(CKA.CKA_VALUE);
            if (attrs.Count == 0 || attrs[0].CannotBeRead)
                throw new InvalidOperationException(
                    "Derived key did not expose CKA_VALUE; the token may not permit reading derived key material.");
            byte[] value = attrs[0].GetValueAsByteArray();
            operationFailed = false;
            return value;
        }
        finally
        {
            DestroyEphemeral(derived, operationFailed);
        }
    }

    /// <summary>
    /// Destroys an ephemeral derived key without letting a cleanup failure hide a real one.
    /// </summary>
    /// <remarks>
    /// A throw from <c>finally</c> <i>replaces</i> an exception already in flight, so a failed
    /// <c>C_DestroyObject</c> would reach the caller in place of whatever actually went wrong. This
    /// suppresses the destroy failure only on that path: when the operation succeeded, the destroy
    /// failure is the only news and is allowed to surface. The key is a session object either way, so
    /// the token collects it at <c>C_CloseSession</c> even when the eager destroy fails.
    /// </remarks>
    private static void DestroyEphemeral(Pkcs11Key derived, bool operationFailed)
    {
        using (derived)
        {
            try
            {
                derived.Destroy();
            }
            catch (Pkcs11Exception) when (operationFailed)
            {
                // Deliberately swallowed: see the remarks. The primary exception is the useful one.
            }
        }
    }
}
