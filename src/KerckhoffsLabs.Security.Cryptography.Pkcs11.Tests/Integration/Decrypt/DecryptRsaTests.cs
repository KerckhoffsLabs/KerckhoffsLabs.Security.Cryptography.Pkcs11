using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Decrypt;

/// <summary>
/// The RSA PKCS#1 v1.5 decryption gate. RSA-OAEP round-trips are covered by the RSAPkcs11 adapter
/// tests (<c>Integration/Adapters/RSAPkcs11Tests.EncryptDecrypt_OaepSha</c>).
/// </summary>
internal static class DecryptRsaTestCases
{
    /// <summary>
    /// <c>DecryptRsaPkcs1V15</c> must throw <see cref="InsecureOperationException"/> by default.
    /// The gate fires before C_DecryptInit, so only a session (no real key) is needed.
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
}

/// <summary>RSA PKCS#1 v1.5 gate against pkcs11-mock (the managed gate fires before C_DecryptInit).</summary>
[Collection("Mock")]
public sealed class DecryptRsaTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void RsaPkcs1V15_ThrowsInsecureOperationException_ByDefault_Mock()
        => DecryptRsaTestCases.Assert_RsaPkcs1V15_GatedByDefault(_backend);
}

[Collection("SoftHsm")]
public sealed class DecryptRsaTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;

    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RsaPkcs1V15_ThrowsInsecureOperationException_ByDefault_SoftHsm()
        => DecryptRsaTestCases.Assert_RsaPkcs1V15_GatedByDefault(_backend);
}
