using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Encrypt;

/// <summary>
/// Shared test logic for RSA-OAEP encrypt/decrypt and the RSA PKCS#1 v1.5 gate.
/// </summary>
internal static class EncryptRsaTestCases
{
    internal static void Assert_RsaOaep_RoundTrips(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var (pub, priv) = TestKeys.GenerateRsa2048KeyPair(session);
            try
            {
                byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("RSA-OAEP round-trip test payload.");

                byte[] ciphertext = session.EncryptRsaOaep(pub, plaintext);
                Assert.NotNull(ciphertext);
                Assert.True(ciphertext.Length > 0);

                byte[] recovered = session.DecryptRsaOaep(priv, ciphertext);
                Assert.Equal(plaintext, recovered);
            }
            finally
            {
                session.DestroyObject(pub);
                session.DestroyObject(priv);
            }
        }
        finally
        {
            session.CloseSession();
        }
    }

    internal static void Assert_RsaPkcs1V15_GatedByDefault(IPkcs11Backend backend)
    {
        // The InsecureOperationException guard fires before any P/Invoke call to C_Encrypt,
        // but a session must still be opened and a key pair generated first.
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var (pub, priv) = TestKeys.GenerateRsa2048KeyPair(session);
            try
            {
                byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("RSA v1.5 test");

#pragma warning disable CS0618 // EncryptRsaPkcs1V15 is intentionally Obsolete
                Assert.Throws<InsecureOperationException>(() =>
                    session.EncryptRsaPkcs1V15(pub, plaintext));
#pragma warning restore CS0618
            }
            finally
            {
                session.DestroyObject(pub);
                session.DestroyObject(priv);
            }
        }
        finally
        {
            session.CloseSession();
        }
    }
}

// ---------------------------------------------------------------------------
// Concrete test class: Mock backend
// ---------------------------------------------------------------------------

/// <summary>
/// RSA tests against pkcs11-mock.
/// The PKCS#1 v1.5 gate fires in managed code before C_EncryptInit and runs
/// unconditionally. RSA-OAEP round-trip requires real crypto and stays SoftHsm-only.
/// </summary>
[Collection("Mock")]
public sealed class EncryptRsaTests_Mock(MockBackendFixture f)
{
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    private readonly MockBackendFixture _backend = f;

    // Crypto-correctness: mock Xor-based encrypt does not implement RSA-OAEP.
    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RsaOaep_RoundTrips_Mock()
        => EncryptRsaTestCases.Assert_RsaOaep_RoundTrips(_backend);

    // Gate-enforcement: InsecureOperationException fires in C# before C_EncryptInit.
    [Fact]
    public void RsaPkcs1V15_ThrowsInsecureOperationException_ByDefault_Mock()
        => EncryptRsaTestCases.Assert_RsaPkcs1V15_GatedByDefault(_backend);
}

// ---------------------------------------------------------------------------
// Concrete test class: SoftHSM backend
// ---------------------------------------------------------------------------

[Collection("SoftHsm")]
public sealed class EncryptRsaTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;

    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;
    public static bool SoftHsmSupportsOaepSha256 => SoftHsmBackendFixture.SoftHsmSupportsOaepSha256;

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsOaepSha256))]
    public void RsaOaep_RoundTrips_SoftHsm()
        => EncryptRsaTestCases.Assert_RsaOaep_RoundTrips(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RsaPkcs1V15_ThrowsInsecureOperationException_ByDefault_SoftHsm()
        => EncryptRsaTestCases.Assert_RsaPkcs1V15_GatedByDefault(_backend);
}
