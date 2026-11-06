using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
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
internal sealed record ExampleCase(
    string Name,
    Type[] Covers,
    CKM[] Requires,
    ExampleBackend MustRunOn,
    Action<IPkcs11Backend> Run,
    bool NeedsUserLogin = false,
    Func<IPkcs11Backend, string?>? Unsupported = null);

/// <summary>Known capability gaps the catalogue's <see cref="ExampleCase.Unsupported"/> gates reuse.</summary>
internal static class ExampleGates
{
    /// <summary>NSS before 3.52 cannot run classic AES-GCM (see <see cref="NssBackendFixture.RequireClassicAesGcm"/>).</summary>
    public static string? ClassicAesGcm(IPkcs11Backend backend) =>
        backend is NssBackendFixture nss && !nss.Library.LowLevelLibrary!.IsBoundThroughV3Interface
            ? "NSS before 3.52 reads CK_GCM_PARAMS without ulIvBits, so classic AES-GCM fails on it"
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

    // A known secret imported as a derive-only generic secret, so a token KDF can be compared with the BCL's.
    private static Pkcs11Key ImportDeriveKey(Pkcs11Session session, byte[] raw)
    {
        using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).Value(raw).Derive().Build();
        return session.ImportKey(template);
    }

    // The token key and the BCL's key bytes are the same key when what one encrypts, the other decrypts.
    private static void AssertSameAesKey(Pkcs11Key tokenKey, byte[] bclKey)
    {
        using var onToken = new AesGcmPkcs11(tokenKey, 16);
        byte[] nonce = RandomNumberGenerator.GetBytes(12), ciphertext = new byte[Message.Length], tag = new byte[16];
        onToken.Encrypt(nonce, Message, ciphertext, tag);
        using var inSoftware = new AesGcm(bclKey, 16);
        byte[] decrypted = new byte[ciphertext.Length];
        inSoftware.Decrypt(nonce, ciphertext, tag, decrypted);
        Assert.Equal(Message, decrypted);
    }

    // The legacy data is made by the BCL with a known key, which the test imports onto the token (under
    // AllowInsecure: the default policy refuses a legacy key); the example must read it back, and the same
    // decryption without the example's lease must be refused. Shared by the 3DES, DES and RC2 cases.
    private static void AssertLegacyCbc(
        Pkcs11Session session, CKK keyType, int keyBytes, int blockBytes, Func<SymmetricAlgorithm> bcl,
        Func<Pkcs11Session, Pkcs11Key, byte[], byte[], byte[]> example, Func<Pkcs11Key, SymmetricAlgorithm> adapter)
    {
        byte[] raw = RandomNumberGenerator.GetBytes(keyBytes), iv = RandomNumberGenerator.GetBytes(blockBytes);
        using SymmetricAlgorithm software = bcl();
        software.Key = raw;
        byte[] ciphertext = software.EncryptCbc(Message, iv, PaddingMode.PKCS7);

        Pkcs11Key key;
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        using (ObjectTemplate template = ObjectTemplate.ForSecretKey(keyType).Value(raw).Decrypt().Build())
            key = session.ImportKey(template);
        using (key)
        {
            Assert.Equal(Message, example(session, key, iv, ciphertext));
            using SymmetricAlgorithm unleased = adapter(key);
            Assert.Throws<CryptoPolicyViolationException>(() => unleased.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7));
        }
    }
}
