using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Verify;

internal static class VerifyEdDsaTestCases
{
    internal static void Assert_Ed25519_RejectsTamperedData(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        var (pub, priv) = TestKeys.GenerateEd25519KeyPair(session);
        try
        {
            byte[] data = System.Text.Encoding.UTF8.GetBytes("Ed25519 tamper");
            byte[] sig = session.SignEd25519(priv, data);
            byte[] tampered = (byte[])data.Clone();
            tampered[0] ^= 0xFF;

            session.VerifyEd25519(pub, tampered, sig, out bool isValid);
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
public sealed class VerifyEdDsaTests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public VerifyEdDsaTests_SoftHsm(SoftHsmBackendFixture f) { _backend = f; }
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ed25519_RejectsTamperedData() => VerifyEdDsaTestCases.Assert_Ed25519_RejectsTamperedData(_backend);
}
