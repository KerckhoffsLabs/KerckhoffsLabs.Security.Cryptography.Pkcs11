using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

/// <summary>The CI backends an example can be required to run on.</summary>
[Flags]
internal enum ExampleBackend
{
    SoftHsm2 = 1,
    Kryoptic = 2,
    Nss = 4,
    BouncyHsm = 8,
    WolfPkcs11 = 16,
    OpenCryptoki = 32,
    FreeHsm = 64,
    CratonHsm = 128,
}

/// <summary>One documentation example, as the tests run it.</summary>
/// <param name="Name"><c>"&lt;Class&gt;.&lt;Method&gt;"</c> of the example in the examples project.</param>
/// <param name="Covers">The adapter types the example documents.</param>
/// <param name="Requires">The mechanisms the backend must advertise for the example to run.</param>
/// <param name="MustRunOn">The backends on which a skip is a failure on the full-backend CI leg.</param>
/// <param name="Run">Calls the example and asserts its outcome.</param>
/// <param name="NeedsUserLogin">The example logs in with the user PIN itself, so it cannot run on a
/// token that refuses <c>C_Login</c> (NSS's login-less crypto token).</param>
/// <param name="Unsupported">Why this backend cannot run the example although it advertises the
/// mechanisms (a known capability gap of that module or version), or <see langword="null"/> when it can.
/// Judged by the same skip-or-fail rule as <paramref name="Requires"/>.</param>
/// <param name="LoadsModule">The example loads the module itself (<c>Pkcs11Library.Load</c>), a second
/// instance next to the fixture's, so <see cref="ExampleRunner"/> applies
/// <see cref="ExampleGates.SecondModuleInstance"/> to it.</param>
internal sealed record ExampleCase(
    string Name,
    Type[] Covers,
    CKM[] Requires,
    ExampleBackend MustRunOn,
    Action<IPkcs11Backend> Run,
    bool NeedsUserLogin = false,
    Func<IPkcs11Backend, string?>? Unsupported = null,
    bool LoadsModule = false);

/// <summary>Known capability gaps the catalogue's <see cref="ExampleCase.Unsupported"/> gates reuse.</summary>
internal static class ExampleGates
{
    /// <summary>NSS before 3.52 cannot run classic AES-GCM (see <see cref="NssBackendFixture.RequireClassicAesGcm"/>).</summary>
    public static string? ClassicAesGcm(IPkcs11Backend backend) =>
        backend is NssBackendFixture nss && !nss.Library.LowLevelLibrary!.IsBoundThroughV3Interface
            ? "NSS before 3.52 reads CK_GCM_PARAMS without ulIvBits, so classic AES-GCM fails on it"
            : null;

    /// <summary>FreeHSM answers <c>CKR_FUNCTION_FAILED</c> to the <c>C_Initialize</c> of a second instance of the
    /// module in a process that already has one, which an example that loads the module itself makes.</summary>
    public static string? SecondModuleInstance(IPkcs11Backend backend) =>
        backend is FreeHsmBackendFixture
            ? "FreeHSM's C_Initialize fails for a second instance of the module in the same process"
            : null;

    /// <summary>opencryptoki answers <c>CKR_TEMPLATE_INCONSISTENT</c> to a decapsulation template without
    /// <c>CKA_VALUE_LEN</c>, which SoftHSM refuses as read-only, so a template that runs on both cannot be written.
    /// <see cref="Pkcs11.Algorithms.MLKemPkcs11"/> probes for the form; an example that passes its own template cannot.</summary>
    public static string? DecapsulationNeedsValueLen(IPkcs11Backend backend) =>
        backend is OpenCryptokiBackendFixture
            ? "opencryptoki needs CKA_VALUE_LEN in a decapsulated key's template, which SoftHSM refuses"
            : null;
}

/// <summary>
/// Every documentation example, with the assertions that prove it does what its page says. Each
/// algorithm's cases live in <c>ExampleCatalog.&lt;Algorithm&gt;.cs</c>, next to its examples class
/// (<c>samples/…/&lt;Family&gt;/&lt;Algorithm&gt;Examples.cs</c>) and its page (<c>docs/examples/</c>).
/// </summary>
internal static partial class ExampleCatalog
{
    // Declared before All: static field initializers run in textual order, and the case lists read these.
    private static readonly byte[] Message = Encoding.UTF8.GetBytes("Pay 100 EUR to account 42.");
    private static readonly byte[] Header = Encoding.UTF8.GetBytes("message-id: 7");

    public static IReadOnlyList<ExampleCase> All { get; } =
    [
        .. GettingStartedCases(),
        .. AesGcmCases(),
        .. AesCcmCases(),
        .. ChaCha20Poly1305Cases(),
        .. AesModeCases(),
        .. RsaCases(),
        .. EcdsaCases(),
        .. EcdhCases(),
        .. MlKemCases(),
        .. MlDsaCases(),
        .. SlhDsaCases(),
        .. Sha2Cases(),
        .. Sha3Cases(),
        .. HmacCases(),
        .. HkdfCases(),
        .. Pbkdf2Cases(),
        .. Sp800108Cases(),
        .. CertificateCases(),
        .. TripleDesCases(),
        .. DesCases(),
        .. Rc2Cases(),
        .. DsaCases(),
        .. Md5Cases(),
        .. Sha1Cases(),
    ];

    /// <summary>The example names, as theory data (a name serializes; a delegate does not).</summary>
    public static TheoryData<string> Names => [.. All.Select(c => c.Name)];

    public static ExampleCase Get(string name) =>
        All.SingleOrDefault(c => c.Name == name) ?? throw new ArgumentException($"No example named {name}.", nameof(name));

    /// <summary><c>"&lt;Class&gt;.&lt;Method&gt;"</c>, from <c>nameof</c> of each, so a rename breaks the build.</summary>
    private static string Name(string examplesClass, string method) => $"{examplesClass}.{method}";

    // Opens a session the backend's way (login or not) and runs an example in it.
    private static void WithSession(IPkcs11Backend backend, Action<Pkcs11Session> body)
    {
        using Pkcs11Session session = backend.OpenSession();
        body(session);
    }

    // The full-flow examples load the module themselves (a second instance of it in this process), log in
    // with the user PIN, and open a key by label. The test provisions that key under a unique label.
    private static string NewLabel() => $"example-{Guid.NewGuid():N}";

    // A copy of the fixture's user PIN, as the caller of an example would read it from its secret store.
    private static SecurePin UserPin(IPkcs11Backend backend) => new(backend.UserPin.Span);

    // Provisions a key under a fresh label, runs the example against the label, runs thenWithKey (if any) on
    // the key opened again by label, destroys every object with the label, and checks that the example, by
    // disposing its own instance of the module, did not finalize the module under the fixture.
    //
    // Where the backend keeps token objects, the key is one, and the provisioning session is closed before the
    // example runs: the login state belongs to the application, not the session, so a session of this process
    // still logged in would make the example's C_Login fail with CKR_USER_ALREADY_LOGGED_IN; and a token
    // object, unlike a session object, outlives the session that made it, as a key provisioned long ago does.
    // A backend without token objects (NSS's write-protected crypto token) gets a session object instead, kept
    // alive by keeping its session open; that token takes no login, so nothing conflicts.
    private static void WithProvisionedKey(
        IPkcs11Backend backend, Func<Pkcs11Session, string, Pkcs11Key> provision, Action<string> example,
        Action<Pkcs11Key>? thenWithKey = null)
    {
        string label = NewLabel();
        using (Pkcs11Session? keeper = backend.SupportsTokenObjects ? null : backend.OpenSession())
        {
            try
            {
                if (keeper is null)
                {
                    using Pkcs11Session provisioning = backend.OpenSession();
                    using (provision(provisioning, label)) { }
                }
                else
                {
                    using (provision(keeper, label)) { }
                }

                example(label);

                if (thenWithKey is not null)
                    WithSessionOrKeeper(backend, keeper, s =>
                    {
                        using Pkcs11Key key = s.OpenKey(label);
                        thenWithKey(key);
                    });
            }
            finally
            {
                WithSessionOrKeeper(backend, keeper, s => DestroyObjectsLabelled(s, label));
            }
        }
        AssertFixtureLibraryStillWorks(backend);
    }

    private static void WithSessionOrKeeper(IPkcs11Backend backend, Pkcs11Session? keeper, Action<Pkcs11Session> body)
    {
        if (keeper is not null)
        {
            body(keeper);
            return;
        }
        using Pkcs11Session session = backend.OpenSession();
        body(session);
    }

    // Destroys every object (both halves of a key pair, a certificate) that carries the label.
    private static void DestroyObjectsLabelled(Pkcs11Session session, string label)
    {
        using ObjectTemplate filter = ObjectTemplate.Empty().Label(label).Build();
        using ReadOnlyDisposableList<Pkcs11Object> objects = session.FindObjects(filter);
        foreach (Pkcs11Object found in objects)
            found.Destroy();
    }

    // Runs a key-generation example, and the page's example that uses the key, under a fresh label; then
    // destroys every object with the label and checks the fixture's library still works.
    private static void WithGeneratedKey(IPkcs11Backend backend, Action<string> body)
    {
        string label = NewLabel();
        try
        {
            body(label);
        }
        finally
        {
            WithSessionOrKeeper(backend, null, s => DestroyObjectsLabelled(s, label));
        }
        AssertFixtureLibraryStillWorks(backend);
    }

    private static readonly CKA[] KeyRoles =
    [
        CKA.CKA_ENCRYPT, CKA.CKA_DECRYPT, CKA.CKA_SIGN, CKA.CKA_VERIFY, CKA.CKA_WRAP, CKA.CKA_UNWRAP,
        CKA.CKA_DERIVE, CKA.CKA_ENCAPSULATE, CKA.CKA_DECAPSULATE,
    ];

    // What a generation example promises, checked on the token: the key (or the named half of a pair) is a
    // token object; a secret or private key is sensitive and non-extractable; and it has exactly the roles
    // given, every other role being off (or not an attribute that key type has). The half is read on its own
    // through GetAttributeValue(KeyHandlePart, ...), in one call.
    private static void AssertGeneratedKey(IPkcs11Backend backend, string label, CKO keyClass, params CKA[] roles)
    {
        using Pkcs11Session session = backend.OpenSession();
        using (ObjectTemplate filter = ObjectTemplate.Empty().Label(label).Attribute(CKA.CKA_CLASS, (ulong)keyClass).Build())
        using (ReadOnlyDisposableList<Pkcs11Object> found = session.FindObjects(filter))
            Assert.True(found.Count == 1, $"Expected one {keyClass} labelled {label}.");

        using Pkcs11Key key = session.OpenKey(label);
        KeyHandlePart part = keyClass is CKO.CKO_PUBLIC_KEY ? KeyHandlePart.Public : KeyHandlePart.Private;
        using ReadOnlyDisposableList<ObjectAttribute> attributes =
            key.GetAttributeValue(part, [CKA.CKA_CLASS, CKA.CKA_TOKEN, CKA.CKA_SENSITIVE, CKA.CKA_EXTRACTABLE, .. KeyRoles]);
        bool IsTrue(CKA type) => attributes.Single(a => a.Type == type) is { CannotBeRead: false } a && a.GetValueAsBool();

        Assert.Equal(keyClass, (CKO)attributes.Single(a => a.Type == CKA.CKA_CLASS).GetValueAsUlong());
        Assert.True(IsTrue(CKA.CKA_TOKEN), $"The {keyClass} is not a token object.");
        foreach (CKA role in KeyRoles)
        {
            bool granted = IsTrue(role);
            Assert.True(granted == roles.Contains(role), $"The {keyClass} has {role} = {granted}.");
        }

        if (keyClass is CKO.CKO_PUBLIC_KEY) return;
        Assert.True(IsTrue(CKA.CKA_SENSITIVE), $"The {keyClass} is not sensitive.");
        Assert.False(IsTrue(CKA.CKA_EXTRACTABLE), $"The {keyClass} is extractable.");
    }

    // A signature scheme's two examples in turn: the generation example provisions the key pair under a fresh
    // label (checkAttributes: and the test checks each half), then the signing example opens it by that label
    // and signs Message. Returns the signature, the public key the signing example exported, and the one the
    // generation example exported.
    private static (byte[] Signature, byte[] PublicKey, byte[] GeneratedPublicKey) GenerateAndSignWithPair(
        IPkcs11Backend backend,
        Func<string, string, SecurePin, string, byte[]> generate,
        Func<string, string, SecurePin, string, byte[], (byte[] Signature, byte[] PublicKey)> sign,
        bool checkAttributes)
    {
        (byte[], byte[], byte[]) result = default;
        WithGeneratedKey(backend, label =>
        {
            using SecurePin pin = UserPin(backend);
            byte[] generated = generate(backend.LibraryPath, backend.TokenLabel, pin, label);
            if (checkAttributes)
            {
                AssertGeneratedKey(backend, label, CKO.CKO_PRIVATE_KEY, CKA.CKA_SIGN);
                AssertGeneratedKey(backend, label, CKO.CKO_PUBLIC_KEY, CKA.CKA_VERIFY);
            }
            (byte[] signature, byte[] publicKey) = sign(backend.LibraryPath, backend.TokenLabel, pin, label, Message);
            result = (signature, publicKey, generated);
        });
        return result;
    }

    // After an example that loaded and disposed its own instance of the module: the fixture's still works.
    private static void AssertFixtureLibraryStillWorks(IPkcs11Backend backend)
    {
        using Pkcs11Session session = backend.OpenSession();
        Assert.Equal(16, session.GenerateRandom(16).Length);
    }

    // A known secret imported under a label as a derive-only generic secret, so a token KDF can be compared
    // with the BCL's.
    private static Pkcs11Key ImportDeriveKey(IPkcs11Backend backend, Pkcs11Session session, string label, byte[] raw)
    {
        using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).OnToken(backend.SupportsTokenObjects).Value(raw).Derive().Build();
        return session.ImportKey(template);
    }

    // What an example encrypted with AES-GCM under a key it derived on the token, the BCL decrypts with the
    // key bytes it derived itself: the two are the same key.
    private static void AssertDecryptsWith(byte[] bclKey, (byte[] Nonce, byte[] Ciphertext, byte[] Tag) sealedMessage)
    {
        using var inSoftware = new AesGcm(bclKey, 16);
        byte[] decrypted = new byte[sealedMessage.Ciphertext.Length];
        inSoftware.Decrypt(sealedMessage.Nonce, sealedMessage.Ciphertext, sealedMessage.Tag, decrypted);
        Assert.Equal(Message, decrypted);
    }

    // What an example encrypted with AES-GCM under a key it derived, the same derivation, run again in a
    // session of the test, decrypts on the token.
    private static void AssertDecryptsWithTokenKey(
        IPkcs11Backend backend, (byte[] Nonce, byte[] Ciphertext, byte[] Tag) sealedMessage, Func<Pkcs11Session, Pkcs11Key> deriveAgain)
    {
        using Pkcs11Session session = backend.OpenSession();
        using Pkcs11Key key = deriveAgain(session);
        using var aesGcm = new AesGcmPkcs11(key, 16);
        byte[] decrypted = new byte[sealedMessage.Ciphertext.Length];
        aesGcm.Decrypt(sealedMessage.Nonce, sealedMessage.Ciphertext, sealedMessage.Tag, decrypted);
        Assert.Equal(Message, decrypted);
    }

    // The BCL counterpart of a legacy CBC example: what the BCL encrypts with a key, the example decrypts with it.
    private static void AssertBclLegacyCbc(int keyBytes, Func<SymmetricAlgorithm> bcl, Func<byte[], byte[], byte[], byte[]> example)
    {
        byte[] raw = RandomNumberGenerator.GetBytes(keyBytes), iv = RandomNumberGenerator.GetBytes(8);
        using SymmetricAlgorithm software = bcl();
        software.Key = raw;
        Assert.Equal(Message, example(raw, iv, software.EncryptCbc(Message, iv, PaddingMode.PKCS7)));
    }

    // The legacy data is made by the BCL with a known key, which the test provisions on the token under a
    // label (under AllowInsecure: the default policy refuses a legacy key); the example, given the label,
    // must read it back, and the same decryption without the example's lease must be refused. Shared by the
    // 3DES, DES and RC2 cases; example(label, iv, ciphertext) runs the whole flow.
    private static void AssertLegacyCbc(
        IPkcs11Backend backend, CKK keyType, int keyBytes, int blockBytes, Func<SymmetricAlgorithm> bcl,
        Func<string, byte[], byte[], byte[]> example, Func<Pkcs11Key, SymmetricAlgorithm> adapter)
    {
        byte[] raw = RandomNumberGenerator.GetBytes(keyBytes), iv = RandomNumberGenerator.GetBytes(blockBytes);
        using SymmetricAlgorithm software = bcl();
        software.Key = raw;
        byte[] ciphertext = software.EncryptCbc(Message, iv, PaddingMode.PKCS7);

        WithProvisionedKey(
            backend,
            (session, label) =>
            {
                using (session.UsePolicy(CryptoPolicy.AllowInsecure))
                using (ObjectTemplate template = ObjectTemplate.ForSecretKey(keyType)
                    .Label(label).OnToken(backend.SupportsTokenObjects).Value(raw).Decrypt().Build())
                    return session.ImportKey(template);
            },
            label => Assert.Equal(Message, example(label, iv, ciphertext)),
            key =>
            {
                using SymmetricAlgorithm unleased = adapter(key);
                Assert.Throws<CryptoPolicyViolationException>(() => unleased.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7));
            });
    }
}
