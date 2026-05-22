using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Verify;

internal static class VerifyEcdsaTestCases
{
    internal static void Assert_RejectsTamperedData(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        var (pub, priv) = TestKeys.GenerateEcP256KeyPair(session);
        try
        {
            byte[] data = System.Text.Encoding.UTF8.GetBytes("phase-2 ECDSA tamper");
            byte[] sig = session.SignEcdsa(priv, data);

            byte[] tampered = (byte[])data.Clone();
            tampered[0] ^= 0xFF;

            session.VerifyEcdsa(pub, tampered, sig, out bool isValid);
            Assert.False(isValid, "Tampered data must not verify.");
        }
        finally
        {
            session.DestroyObject(priv);
            session.DestroyObject(pub);
            session.Logout();
            session.CloseSession();
        }
    }
}

[Collection("SoftHsm")]
public sealed class VerifyEcdsaTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;

    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RejectsTamperedData() => VerifyEcdsaTestCases.Assert_RejectsTamperedData(_backend);
}
