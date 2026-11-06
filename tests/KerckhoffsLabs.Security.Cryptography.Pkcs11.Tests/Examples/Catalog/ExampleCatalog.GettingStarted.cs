using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/guide/getting-started.md
internal static partial class ExampleCatalog
{
    private static ExampleCase[] GettingStartedCases() =>
    [
        new(
            Name(nameof(GettingStartedExamples), nameof(GettingStartedExamples.ReadPinFromEnvironment)),
            [],
            [],
            ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            AssertReadPinFromEnvironment,
            NeedsUserLogin: true),
        new(
            Name(nameof(GettingStartedExamples), nameof(GettingStartedExamples.EncryptAndDecryptWithTokenKey)),
            [],
            [CKM.CKM_AES_KEY_GEN, CKM.CKM_AES_GCM],
            ExampleBackend.SoftHsm2 | ExampleBackend.Kryoptic,
            AssertEncryptAndDecryptWithTokenKey,
            NeedsUserLogin: true,
            Unsupported: b => ExampleGates.ClassicAesGcm(b) ?? ExampleGates.SecondModuleInstance(b)),
    ];

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
