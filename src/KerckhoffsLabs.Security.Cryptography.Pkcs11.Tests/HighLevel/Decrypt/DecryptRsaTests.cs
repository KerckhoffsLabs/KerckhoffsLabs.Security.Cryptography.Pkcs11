using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Decrypt;

/// <summary>
/// Shared test logic for RSA decryption: the legacy PKCS#1 v1.5 gate and OAEP round-trip.
/// The gate test runs on both backends (managed check fires before P/Invoke).
/// The OAEP round-trip requires a real RSA key pair and is SoftHsm-only.
/// </summary>
internal static class DecryptRsaTestCases
{
    /// <summary>
    /// <see cref="Session.DecryptRsaPkcs1V15"/> must throw <see cref="InsecureOperationException"/>
    /// by default. The gate fires before C_DecryptInit, so only a session (no real key) is
    /// needed. CS0618 is suppressed at the call site.
    /// </summary>
    internal static void Assert_RsaPkcs1V15_GatedByDefault(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var (pub, priv) = TestKeys.GenerateRsa2048KeyPair(session);
            try
            {
                byte[] fakeCiphertext = new byte[256]; // RSA-2048 output size

#pragma warning disable CS0618 // DecryptRsaPkcs1V15 is intentionally Obsolete
                Assert.Throws<InsecureOperationException>(() =>
                    session.DecryptRsaPkcs1V15(priv, fakeCiphertext));
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

    /// <summary>
    /// Full RSA-OAEP encrypt-then-decrypt round-trip. Requires real RSA key generation
    /// and RSA-OAEP semantics — SoftHsm-only.
    /// </summary>
    internal static void Assert_RsaOaep_RoundTrip(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var (pub, priv) = TestKeys.GenerateRsa2048KeyPair(session);
            try
            {
                byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("RSA-OAEP decrypt round-trip test.");

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
}

// ---------------------------------------------------------------------------
// Concrete test class: Mock backend
// ---------------------------------------------------------------------------

/// <summary>
/// RSA decryption tests against pkcs11-mock.
/// The PKCS#1 v1.5 gate fires in managed code before C_DecryptInit and runs
/// unconditionally. RSA-OAEP round-trip requires real crypto and stays SoftHsm-only.
/// </summary>
[Collection("Mock")]
public sealed class DecryptRsaTests_Mock(MockBackendFixture f)
{
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    private readonly MockBackendFixture _backend = f;

    // Gate-enforcement: InsecureOperationException fires in C# before C_DecryptInit.
    [Fact]
    public void RsaPkcs1V15_ThrowsInsecureOperationException_ByDefault_Mock()
        => DecryptRsaTestCases.Assert_RsaPkcs1V15_GatedByDefault(_backend);

    // Crypto-correctness: mock Xor-based decrypt does not implement RSA-OAEP.
    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RsaOaep_RoundTrip_Mock()
        => DecryptRsaTestCases.Assert_RsaOaep_RoundTrip(_backend);
}

// ---------------------------------------------------------------------------
// Concrete test class: SoftHSM backend
// ---------------------------------------------------------------------------

[Collection("SoftHsm")]
public sealed class DecryptRsaTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;

    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RsaPkcs1V15_ThrowsInsecureOperationException_ByDefault_SoftHsm()
        => DecryptRsaTestCases.Assert_RsaPkcs1V15_GatedByDefault(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RsaOaep_RoundTrip_SoftHsm()
        => DecryptRsaTestCases.Assert_RsaOaep_RoundTrip(_backend);
}
