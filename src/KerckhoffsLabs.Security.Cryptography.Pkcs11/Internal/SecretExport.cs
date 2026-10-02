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
/// <see cref="KeyTemplateRequest"/>, nor, for a raw ECDH secret, the <c>CKD_NULL</c> derivation. The
/// session accepts that waiver only inside the read-back scope that decided the export, and the scope's state
/// (the pinned policy and request) lives only until it is disposed, so no other request is affected.
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
    internal static SecretExportKind Classify(Operation operation, Mechanism mechanism, string paramName)
    {
        // A second key in the parameters takes part in the output, but the export decision is about the
        // base key alone; reading the output back would expose that second key. Refused whatever the policy.
        string? secondKey = mechanism.Parameters switch
        {
            CkmSp800108KdfParams { HasKeySegment: true } =>
                "a key segment (Sp800108KdfBuilder.Key) feeds another key's value into the PRF input, and the output " +
                "would reveal it: with a CMAC PRF and a base key of known value, it decrypts back to that key",
            CkmHkdfParams { HasSaltKey: true } =>
                "a salt key (CkmHkdfParams.WithSaltKey) makes the output an HMAC under that key, which the export " +
                "decision never judged",
            _ => null,
        };
        if (secondKey is not null)
            throw new ArgumentException(
                $"{MechanismNames.Of(mechanism.Type)} cannot be used to export a secret with these parameters: {secondKey}. " +
                "Derive a key that stays on the token instead.",
                paramName);

        SecretExportKind? kind = (operation, mechanism.Type, mechanism.Parameters) switch
        {
            (Operation.Derive, CKM.CKM_ECDH1_DERIVE or CKM.CKM_ECDH1_COFACTOR_DERIVE, CkmEcdh1DeriveParams ecdh)
                when !ecdh.PublicData.IsEmpty => SecretExportKind.EcdhSharedSecret,
            (Operation.Derive, CKM.CKM_HKDF_DERIVE, CkmHkdfParams) => SecretExportKind.KdfOutput,
            // Additional derived keys would be further keys created by the same call, which the
            // read-back neither reads nor destroys.
            (Operation.Derive, CKM.CKM_SP800_108_COUNTER_KDF or CKM.CKM_SP800_108_FEEDBACK_KDF or CKM.CKM_SP800_108_DOUBLE_PIPELINE_KDF,
                CkmSp800108KdfParams sp800108) when sp800108.AdditionalKeyTemplates.Count == 0 => SecretExportKind.KdfOutput,
            (Operation.Generate, CKM.CKM_PKCS5_PBKD2, CkmPkcs5Pbkd2Params) => SecretExportKind.PasswordKdfOutput,
            // Only ML-KEM: the v3.2 KEM entry points also accept RSA PKCS#1 v1.5, and reading back a
            // v1.5 decapsulation would be a padding oracle.
            (Operation.Encapsulate or Operation.Decapsulate, CKM.CKM_ML_KEM, _) => SecretExportKind.KemSharedSecret,
            _ => null,
        };

        return kind ?? throw new ArgumentException(Refusal(operation, mechanism), paramName);
    }

    /// <summary>
    /// Why <paramref name="mechanism"/> cannot be read back through <paramref name="operation"/>: another read-back
    /// takes it, its parameters have the wrong shape, or no read-back takes it at all.
    /// </summary>
    private static string Refusal(Operation operation, Mechanism mechanism)
    {
        string name = MechanismNames.Of(mechanism.Type);
        Operation? home = mechanism.Type switch
        {
            CKM.CKM_ECDH1_DERIVE or CKM.CKM_ECDH1_COFACTOR_DERIVE or CKM.CKM_HKDF_DERIVE
                or CKM.CKM_SP800_108_COUNTER_KDF or CKM.CKM_SP800_108_FEEDBACK_KDF or CKM.CKM_SP800_108_DOUBLE_PIPELINE_KDF => Operation.Derive,
            CKM.CKM_PKCS5_PBKD2 => Operation.Generate,
            CKM.CKM_ML_KEM => operation is Operation.Encapsulate or Operation.Decapsulate ? operation : Operation.Encapsulate,
            _ => null,
        };

        if (home is { } h && h != operation)
            return $"{name} is read back with {EntryPoint(h)}, not here.";

        string? shape = mechanism.Parameters switch
        {
            _ when home is null => null,
            CkmEcdh1DeriveParams { PublicData.IsEmpty: true } =>
                "it needs the peer's public point (CkmEcdh1DeriveParams.ForPeer)",
            CkmSp800108KdfParams { AdditionalKeyTemplates.Count: > 0 } =>
                "it derives additional keys, which the read-back would neither read nor destroy",
            _ when mechanism.Type is CKM.CKM_ECDH1_DERIVE or CKM.CKM_ECDH1_COFACTOR_DERIVE => "it requires CkmEcdh1DeriveParams",
            _ when mechanism.Type is CKM.CKM_HKDF_DERIVE => "it requires CkmHkdfParams",
            _ when mechanism.Type is CKM.CKM_PKCS5_PBKD2 => "it requires CkmPkcs5Pbkd2Params",
            _ => "it requires CkmSp800108KdfParams",
        };
        if (shape is not null)
            return $"{name} cannot be used to export a secret with these parameters: {shape}.";

        return $"{name} cannot be used to export a secret here. {Supported(operation)} " +
               "Other mechanisms can derive keys that stay on the token, but their output is not read back: " +
               "several of them would return the base key itself, or an encryption of it.";
    }

    private static string EntryPoint(Operation operation) => operation switch
    {
        Operation.Derive => "Pkcs11Key.DeriveAndExportSecret on the base key",
        Operation.Generate => "Pkcs11Workspace.DeriveAndExportSecret",
        _ => "Pkcs11Key.EncapsulateAndExportSecret / DecapsulateAndExportSecret",
    };

    private static string Supported(Operation operation) => operation switch
    {
        Operation.Derive =>
            "Supported: CKM_ECDH1_DERIVE and CKM_ECDH1_COFACTOR_DERIVE with a peer public point, CKM_HKDF_DERIVE " +
            "with CkmHkdfParams and no salt key, and the SP 800-108 counter, feedback and double-pipeline KDFs without " +
            "additional derived keys or key segments.",
        Operation.Generate => "Supported: CKM_PKCS5_PBKD2 with CkmPkcs5Pbkd2Params.",
        _ => "Supported: CKM_ML_KEM.",
    };

    /// <summary>
    /// Submits the export to the effective policy — logging and throwing on denial — and returns the scope
    /// the whole read-back must run in (<see cref="Pkcs11Session.BeginExport"/>): it holds the session and
    /// pins the policy that allowed the export until disposed.
    /// </summary>
    /// <exception cref="CryptoPolicyViolationException">The policy refused the export.</exception>
    internal static IDisposable Authorize(Pkcs11Session session, SecretExportKind kind, CKM mechanism, CKO? baseKeyClass, CKK? baseKeyType)
    {
        var request = new SecretExportRequest(kind)
        {
            Mechanism = mechanism,
            BaseKeyClass = baseKeyClass,
            BaseKeyType = baseKeyType,
        };
        return session.BeginExport(request);
    }

    /// <summary>
    /// The ephemeral key's template: a session generic secret that can be read and nothing else — not
    /// stored on the token, not copyable, with every usage flag off. Stated in full rather than left to
    /// token defaults, several of which (the usage flags) default to true.
    /// </summary>
    /// <remarks>
    /// <c>CKA_MODIFIABLE=false</c> is deliberately absent. SoftHSM applies it while it is still writing
    /// the template: on <c>C_DeriveKey</c> every attribute after it is refused with
    /// <c>CKR_ATTRIBUTE_READ_ONLY</c>. It would add little anyway: the key exists for one call and its
    /// handle never leaves the library.
    /// </remarks>
    /// <param name="valueLength">The <c>CKA_VALUE_LEN</c> to request, or <see langword="null"/> to omit it.</param>
    /// <returns>Attributes the caller owns; disposing the list releases them.</returns>
    internal static ReadOnlyDisposableList<ObjectAttribute> EphemeralTemplate(int? valueLength)
    {
        List<ObjectAttribute> template =
        [
            new(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            new(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET),
            new(CKA.CKA_TOKEN, false),
            new(CKA.CKA_SENSITIVE, false),
            new(CKA.CKA_EXTRACTABLE, true),
            new(CKA.CKA_COPYABLE, false),
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
        return new ReadOnlyDisposableList<ObjectAttribute>(template);
    }

    /// <summary>Creates the ephemeral key from the library's template, through one PKCS#11 function.</summary>
    /// <param name="template">The ephemeral key's template, to hand to the session with the export kind.</param>
    /// <returns>The handle of the ephemeral key.</returns>
    internal delegate ObjectHandle EphemeralKeyFactory(List<ObjectAttribute> template);

    /// <summary>Checks a secret just read back; throws to refuse it, and the destination is then zeroed.</summary>
    internal delegate void SecretCheck(ReadOnlySpan<byte> secret);

    /// <summary>
    /// The part every read-back shares once the export is authorized: build the ephemeral template,
    /// create the key with <paramref name="create"/>, then copy its value into
    /// <paramref name="destination"/> and destroy it (<see cref="ReadAndDestroy"/>).
    /// </summary>
    /// <param name="session">The session the key is created and destroyed on.</param>
    /// <param name="valueLength">The <c>CKA_VALUE_LEN</c> to request, or <see langword="null"/> to omit it.</param>
    /// <param name="create">Creates the ephemeral key from the template.</param>
    /// <param name="destination">Receives the secret; zeroed if reading, destroying or <paramref name="check"/> fails.</param>
    /// <param name="check">Refuses a secret of a value the read-back must not return, or <see langword="null"/>.</param>
    internal static void Export(
        Pkcs11Session session, int? valueLength, EphemeralKeyFactory create, Span<byte> destination, SecretCheck? check = null)
    {
        using ReadOnlyDisposableList<ObjectAttribute> template = EphemeralTemplate(valueLength);
        ObjectHandle ephemeral = create([.. template]);
        ReadAndDestroy(session, ephemeral, destination);
        if (check is not null)
        {
            try
            {
                check(destination);
            }
            catch
            {
                CryptographicOperations.ZeroMemory(destination);
                throw;
            }
        }
        session.LogExported();
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
