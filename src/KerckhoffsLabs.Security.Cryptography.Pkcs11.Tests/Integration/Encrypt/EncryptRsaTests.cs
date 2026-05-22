using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>
/// The RSA PKCS#1 v1.5 encryption gate. RSA-OAEP round-trips are covered by the RSAPkcs11 adapter
/// tests (<c>Integration/Adapters/RSAPkcs11Tests.EncryptDecrypt_OaepSha</c>).
/// </summary>
internal static class EncryptRsaTestCases
{
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

/// <summary>RSA PKCS#1 v1.5 gate against pkcs11-mock (the managed gate fires before C_EncryptInit).</summary>
[Collection("Mock")]
public sealed class EncryptRsaTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void RsaPkcs1V15_ThrowsInsecureOperationException_ByDefault_Mock()
        => EncryptRsaTestCases.Assert_RsaPkcs1V15_GatedByDefault(_backend);
}

[Collection("SoftHsm")]
public sealed class EncryptRsaTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;

    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RsaPkcs1V15_ThrowsInsecureOperationException_ByDefault_SoftHsm()
        => EncryptRsaTestCases.Assert_RsaPkcs1V15_GatedByDefault(_backend);
}
