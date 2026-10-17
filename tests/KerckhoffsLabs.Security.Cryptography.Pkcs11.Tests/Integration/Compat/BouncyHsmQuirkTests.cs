using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Compat;

/// <summary>
/// One test per gate on <see cref="BouncyHsmBackendFixture"/>: each reproduces a known BouncyHsm bug
/// directly and asserts that it is still there. When a submodule bump brings the upstream fix, the
/// matching test fails, telling us to remove the gate so the shared test cases run again.
/// </summary>
[Collection("BouncyHsm")]
public sealed class BouncyHsmQuirkTests(BouncyHsmBackendFixture backend)
{
    private readonly IPkcs11Backend _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EmptyDigest_QuirkStillPresent()
    {
        using var session = _backend.OpenSession();

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => session.Digest(new Mechanism(CKM.CKM_SHA256), []));

        Assert.True(ex.ReturnValue == CKR.CKR_ARGUMENTS_BAD,
            $"harrison314/BouncyHsm#115 looks fixed (C_Digest of empty data returned {ex.ReturnValue}): " +
            "set BouncyHsmBackendFixture.BouncyHsmAcceptsEmptyInput to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EmptyHmac_QuirkStillPresent()
    {
        using var session = _backend.OpenSession();
        string label = $"quirk-hmac-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).Value(RandomNumberGenerator.GetBytes(32)).Sign().Verify().Build();
        using var key = session.ImportKey(tpl);
        try
        {
            var ex = Assert.ThrowsAny<Pkcs11Exception>(() => key.Sign(new Mechanism(CKM.CKM_SHA256_HMAC), []));

            Assert.True(ex.ReturnValue == CKR.CKR_GENERAL_ERROR,
                $"harrison314/BouncyHsm#115 looks fixed (C_Sign of empty data returned {ex.ReturnValue}): " +
                "set BouncyHsmBackendFixture.BouncyHsmAcceptsEmptyInput to true and delete this test.");
        }
        finally { key.Destroy(); }
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void OutOfRangePssSignature_QuirkStillPresent()
    {
        using var session = _backend.OpenSession();
        string label = $"quirk-pss-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().ModulusBits(2048).PublicExponent([0x01, 0x00, 0x01]).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA).Label(label).Id(id).Sign().Build();
        using var key = session.GenerateKeyPair(new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), pubTpl, privTpl);
        var pss = new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32));

        // 256 bytes of 0xFF is greater than any 2048-bit modulus.
        byte[] outOfRange = Enumerable.Repeat((byte)0xFF, 256).ToArray();
        try
        {
            var ex = Record.Exception(() => key.Verify(pss, "abc"u8, outOfRange));

            Assert.True(ex is Pkcs11Exception { ReturnValue: CKR.CKR_GENERAL_ERROR },
                "harrison314/BouncyHsm#116 looks fixed (an out-of-range PSS signature no longer gives " +
                $"CKR_GENERAL_ERROR; got {ex?.GetType().Name ?? "no exception"}): set " +
                "BouncyHsmBackendFixture.BouncyHsmRejectsOutOfRangeSignatures to true and delete this test.");
        }
        finally { key.Destroy(); }
    }
}
