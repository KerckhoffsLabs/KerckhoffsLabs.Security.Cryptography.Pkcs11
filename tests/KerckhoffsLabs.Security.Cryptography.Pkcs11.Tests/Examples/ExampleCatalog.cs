using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;
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
internal sealed record ExampleCase(
    string Name,
    Type[] Covers,
    CKM[] Requires,
    ExampleBackend MustRunOn,
    Action<IPkcs11Backend> Run,
    bool NeedsUserLogin = false);

/// <summary>Every documentation example, with the assertions that prove it does what its page says.</summary>
internal static class ExampleCatalog
{
    private static readonly byte[] Message = Encoding.UTF8.GetBytes("Pay 100 EUR to account 42.");

    public static IReadOnlyList<ExampleCase> All { get; } =
    [
        new(
            $"{nameof(GettingStartedExamples)}.{nameof(GettingStartedExamples.ReadPinFromEnvironment)}",
            [],
            [],
            ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            AssertReadPinFromEnvironment,
            NeedsUserLogin: true),
        new(
            $"{nameof(GettingStartedExamples)}.{nameof(GettingStartedExamples.EncryptAndDecryptWithTokenKey)}",
            [],
            [CKM.CKM_AES_KEY_GEN, CKM.CKM_AES_GCM],
            ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            AssertEncryptAndDecryptWithTokenKey,
            NeedsUserLogin: true),
    ];

    /// <summary>The example names, as theory data (a name serializes; a delegate does not).</summary>
    public static TheoryData<string> Names => [.. All.Select(c => c.Name)];

    public static ExampleCase Get(string name) =>
        All.SingleOrDefault(c => c.Name == name) ?? throw new ArgumentException($"No example named {name}.", nameof(name));

    private static void AssertReadPinFromEnvironment(IPkcs11Backend backend)
    {
        string variable = $"KL_EXAMPLE_PIN_{Guid.NewGuid():N}";
        Environment.SetEnvironmentVariable(variable, Encoding.UTF8.GetString(backend.UserPin.Span));
        try
        {
            using SecurePin pin = GettingStartedExamples.ReadPinFromEnvironment(variable);
            using Pkcs11Session session = backend.Library.OpenSessionWithPin(backend.TokenLabel, CKU.CKU_USER, pin);
            Assert.Equal(16, session.GenerateRandom(16).Length);
        }
        finally
        {
            Environment.SetEnvironmentVariable(variable, null);
        }

        var unset = Assert.Throws<InvalidOperationException>(() => GettingStartedExamples.ReadPinFromEnvironment(variable));
        Assert.Contains(variable, unset.Message, StringComparison.Ordinal);
    }

    private static void AssertEncryptAndDecryptWithTokenKey(IPkcs11Backend backend)
    {
        using (var pin = new SecurePin(backend.UserPin.Span))
            Assert.Equal(Message, GettingStartedExamples.EncryptAndDecryptWithTokenKey(backend.LibraryPath, backend.TokenLabel, pin, Message));

        // The example loaded the module a second time and disposed it: the fixture's own library must
        // still work, so disposing the example's instance did not finalize the module under it.
        using Pkcs11Session session = backend.OpenSession();
        Assert.Equal(16, session.GenerateRandom(16).Length);
    }
}
