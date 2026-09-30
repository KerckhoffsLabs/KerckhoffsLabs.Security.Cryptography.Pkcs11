using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// The engine behind the public read-back operations (<see cref="Pkcs11Key.DeriveAndExportSecret"/>,
/// <see cref="Pkcs11Key.EncapsulateAndExportSecret"/>, <see cref="Pkcs11Key.DecapsulateAndExportSecret"/>,
/// <see cref="Pkcs11Workspace.DeriveAndExportSecret"/>): decide which mechanisms may be read back at
/// all, submit the export to the policy, create the ephemeral key, copy its value out and destroy it.
/// </summary>
/// <remarks>
/// <para>
/// Reading a secret back means creating a key that is extractable and not sensitive, then reading its
/// <c>CKA_VALUE</c>. A generic "derive anything, then read it" would turn every derivation mechanism
/// into a key-extraction tool — <c>CKM_XOR_BASE_AND_DATA</c>, <c>CKM_CONCATENATE_BASE_AND_KEY</c>,
/// <c>CKM_EXTRACT_KEY_FROM_KEY</c> or <c>CKM_AES_ECB_ENCRYPT_DATA</c> read back the base key or an
/// encryption of it — so the mechanisms are a closed list, keyed on the operation, the mechanism and
/// the shape of its parameters. Everything else is refused with <see cref="ArgumentException"/>,
/// whatever the policy says.
/// </para>
/// <para>
/// The ephemeral key's template is the library's own and is passed to the session with the export
/// kind, as an argument of that one call: the session then does not judge that template again as a
/// <see cref="KeyTemplateRequest"/>, nor, for a raw ECDH secret, the <c>CKD_NULL</c> derivation. No
/// state is left on the session, so no other request is affected.
/// </para>
/// </remarks>
internal static class SecretExport
{
    /// <summary>The PKCS#11 function a read-back goes through.</summary>
    internal enum Operation
    {
        /// <summary><c>C_DeriveKey</c> from a base key.</summary>
        Derive,
        /// <summary><c>C_GenerateKey</c>, for a password-based KDF with no base key.</summary>
        Generate,
        /// <summary><c>C_EncapsulateKey</c>.</summary>
        Encapsulate,
        /// <summary><c>C_DecapsulateKey</c>.</summary>
        Decapsulate,
    }

    /// <summary>
    /// Returns the export kind a read-back of <paramref name="mechanism"/> through
    /// <paramref name="operation"/> amounts to, or throws when it is not one of the supported shapes.
    /// </summary>
    /// <exception cref="ArgumentException">The mechanism, or the shape of its parameters, cannot be read back.</exception>
    internal static KeyMaterialExportKind Classify(Operation operation, Mechanism mechanism, string paramName)
    {
        KeyMaterialExportKind? kind = (operation, mechanism.Type, mechanism.Parameters) switch
        {
            (Operation.Derive, CKM.CKM_ECDH1_DERIVE or CKM.CKM_ECDH1_COFACTOR_DERIVE, CkmEcdh1DeriveParams ecdh)
                when !ecdh.PublicData.IsEmpty => KeyMaterialExportKind.EcdhSharedSecret,
            (Operation.Derive, CKM.CKM_HKDF_DERIVE, CkmHkdfParams) => KeyMaterialExportKind.KdfOutput,
            // Additional derived keys would be further keys created by the same call, which the
            // read-back neither reads nor destroys.
            (Operation.Derive, CKM.CKM_SP800_108_COUNTER_KDF or CKM.CKM_SP800_108_FEEDBACK_KDF or CKM.CKM_SP800_108_DOUBLE_PIPELINE_KDF,
                CkmSp800108KdfParams sp800108) when sp800108.AdditionalKeyTemplates.Count == 0 => KeyMaterialExportKind.KdfOutput,
            (Operation.Generate, CKM.CKM_PKCS5_PBKD2, CkmPkcs5Pbkd2Params) => KeyMaterialExportKind.PasswordKdfOutput,
            // Only ML-KEM: the v3.2 KEM entry points also accept RSA PKCS#1 v1.5, and reading back a
            // v1.5 decapsulation would be a padding oracle.
            (Operation.Encapsulate or Operation.Decapsulate, CKM.CKM_ML_KEM, _) => KeyMaterialExportKind.KemSharedSecret,
            _ => null,
        };

        return kind ?? throw new ArgumentException(
            $"{MechanismNames.Of(mechanism.Type)} cannot be used to export a secret here. {Supported(operation)} " +
            "Other mechanisms can derive keys that stay on the token, but their output is not read back: " +
            "several of them would return the base key itself, or an encryption of it.",
            paramName);
    }

    private static string Supported(Operation operation) => operation switch
    {
        Operation.Derive =>
            "Supported: CKM_ECDH1_DERIVE and CKM_ECDH1_COFACTOR_DERIVE with a peer public point, CKM_HKDF_DERIVE " +
            "with CkmHkdfParams, and the SP 800-108 counter, feedback and double-pipeline KDFs without additional derived keys.",
        Operation.Generate => "Supported: CKM_PKCS5_PBKD2 with CkmPkcs5Pbkd2Params.",
        _ => "Supported: CKM_ML_KEM.",
    };

    /// <summary>
    /// Submits the export to the effective policy — logging and throwing on denial — and logs it when
    /// allowed: an allowed export is the one decision that lets secret bytes leave the token.
    /// </summary>
    /// <exception cref="CryptoPolicyViolationException">The policy refused the export.</exception>
    internal static void Authorize(Pkcs11Session session, KeyMaterialExportKind kind, CKM mechanism, CKO? baseKeyClass, CKK? baseKeyType)
    {
        var request = new KeyMaterialExportRequest(kind)
        {
            Mechanism = mechanism,
            BaseKeyClass = baseKeyClass,
            BaseKeyType = baseKeyType,
        };
        session.Enforce(request);
        session.LogExportAllowed(request);
    }

    /// <summary>
    /// The ephemeral key's template: a session generic secret that can be read and nothing else — not
    /// stored on the token, not copyable or modifiable, with every usage flag off. Stated in full rather
    /// than left to token defaults, several of which (the usage flags) default to true.
    /// </summary>
    /// <param name="valueLength">The <c>CKA_VALUE_LEN</c> to request, or <see langword="null"/> to omit it.</param>
    /// <returns>Attributes the caller owns and must dispose.</returns>
    internal static List<ObjectAttribute> EphemeralTemplate(int? valueLength)
    {
        List<ObjectAttribute> template =
        [
            new(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            new(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET),
            new(CKA.CKA_TOKEN, false),
            new(CKA.CKA_SENSITIVE, false),
            new(CKA.CKA_EXTRACTABLE, true),
            new(CKA.CKA_COPYABLE, false),
            new(CKA.CKA_MODIFIABLE, false),
            new(CKA.CKA_ENCRYPT, false),
            new(CKA.CKA_DECRYPT, false),
            new(CKA.CKA_SIGN, false),
            new(CKA.CKA_VERIFY, false),
            new(CKA.CKA_WRAP, false),
            new(CKA.CKA_UNWRAP, false),
            new(CKA.CKA_DERIVE, false),
        ];
        if (valueLength is int length)
            template.Add(new ObjectAttribute(CKA.CKA_VALUE_LEN, (ulong)length));
        return template;
    }

    /// <summary>Disposes every attribute of a template built by <see cref="EphemeralTemplate"/>.</summary>
    internal static void Release(List<ObjectAttribute> template)
    {
        foreach (ObjectAttribute attribute in template)
            attribute.Dispose();
    }

    /// <summary>
    /// Copies the ephemeral key's value into <paramref name="destination"/>, then destroys the key.
    /// On any failure — including a failed destroy — <paramref name="destination"/> is zeroed, so a
    /// secret is never handed back alongside an exception.
    /// </summary>
    /// <remarks>
    /// The destroy runs whatever happens. When the read already failed, a destroy failure is dropped
    /// so it cannot replace the useful exception; the key is a session object, collected at
    /// <c>C_CloseSession</c> anyway. When the read succeeded, the destroy failure is the only news and
    /// surfaces as the token reported it.
    /// </remarks>
    /// <exception cref="CryptographicException">The token did not expose the value, or produced a value of another length.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_GetAttributeValue</c> or <c>C_DestroyObject</c>.</exception>
    internal static void ReadAndDestroy(Pkcs11Session session, ObjectHandle ephemeral, Span<byte> destination)
    {
        try
        {
            bool readFailed = true;
            try
            {
                using ReadOnlyDisposableList<ObjectAttribute> attrs = session.GetAttributeValue(ephemeral, [CKA.CKA_VALUE]);
                ObjectAttribute value = attrs[0];
                if (value.CannotBeRead)
                    throw new CryptographicException(
                        "The token did not expose the value of the ephemeral extractable key it created, so the secret cannot be read back.");
                if (value.ValueLength != destination.Length)
                    throw new CryptographicException(
                        $"The token produced a {value.ValueLength}-byte secret; {destination.Length} bytes were requested.");
                value.CopyValueTo(destination);
                readFailed = false;
            }
            finally
            {
                Destroy(session, ephemeral, readFailed);
            }
        }
        catch
        {
            CryptographicOperations.ZeroMemory(destination);
            throw;
        }
    }

    private static void Destroy(Pkcs11Session session, ObjectHandle ephemeral, bool readFailed)
    {
        try
        {
            session.DestroyObject(ephemeral);
        }
        catch (Pkcs11Exception) when (readFailed)
        {
            // Deliberately dropped: see ReadAndDestroy. The read's exception is the useful one.
        }
    }
}
