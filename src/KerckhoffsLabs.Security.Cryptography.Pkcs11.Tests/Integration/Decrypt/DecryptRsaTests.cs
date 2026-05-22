using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
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
    /// RSA PKCS#1 v1.5 decryption (CKM_RSA_PKCS) must throw <see cref="InsecureOperationException"/>
    /// by default. The gate fires before C_DecryptInit, so only a session (no real key) is needed.
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

                // CKM_RSA_PKCS (PKCS#1 v1.5) is gated by Session.GuardMechanism; the same gate the
                // RSAPkcs11.Decrypt(RSAEncryptionPadding.Pkcs1) path relies on.
                using var mech = new Mechanism(CKM.CKM_RSA_PKCS);
                Assert.Throws<InsecureOperationException>(() =>
                    session.Decrypt(mech, priv, fakeCiphertext));
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
