using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Verify;

internal static class VerifyRsaPssTestCases
{
    internal static void Assert_RejectsTamperedData(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        var (pub, priv) = TestKeys.GenerateRsa2048SigningKeyPair(session);
        try
        {
            byte[] data = System.Text.Encoding.UTF8.GetBytes("original");
            byte[] sig = session.SignRsaPss(priv, data);

            byte[] tamperedData = (byte[])data.Clone();
            tamperedData[0] ^= 0xFF;

            session.VerifyRsaPss(pub, tamperedData, sig, out bool isValid);
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

    internal static void Assert_RejectsTamperedSignature(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        var (pub, priv) = TestKeys.GenerateRsa2048SigningKeyPair(session);
        try
        {
            byte[] data = System.Text.Encoding.UTF8.GetBytes("phase-2 tamper test");
            byte[] sig = session.SignRsaPss(priv, data);

            byte[] tamperedSig = (byte[])sig.Clone();
            tamperedSig[^1] ^= 0xFF;

            session.VerifyRsaPss(pub, data, tamperedSig, out bool isValid);
            Assert.False(isValid, "Tampered signature must not verify.");
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
public sealed class VerifyRsaPssTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;

    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RejectsTamperedData() => VerifyRsaPssTestCases.Assert_RejectsTamperedData(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RejectsTamperedSignature() => VerifyRsaPssTestCases.Assert_RejectsTamperedSignature(_backend);
}
