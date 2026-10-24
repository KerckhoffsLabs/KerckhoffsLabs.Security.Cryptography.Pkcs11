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

        var ex = Record.Exception(() => session.Digest(new Mechanism(CKM.CKM_SHA256), []));

        Assert.True(ex is Pkcs11Exception { ReturnValue: CKR.CKR_DATA_LEN_RANGE },
            "C_Digest of empty data no longer gives CKR_DATA_LEN_RANGE " +
            $"(got {(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name ?? "no exception"}): set " +
            "BouncyHsmBackendFixture.BouncyHsmAcceptsEmptyDigest to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EmptySignature_QuirkStillPresent()
    {
        using var session = _backend.OpenSession();
        string label = $"quirk-emptysig-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().ModulusBits(2048).PublicExponent([0x01, 0x00, 0x01]).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA).Label(label).Id(id).Sign().Build();
        using var key = session.GenerateKeyPair(new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), pubTpl, privTpl);
        var pss = new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32));
        try
        {
            var ex = Record.Exception(() => key.Verify(pss, "abc"u8, []));

            Assert.True(ex is Pkcs11Exception { ReturnValue: CKR.CKR_ARGUMENTS_BAD },
                "C_Verify of an empty signature no longer gives CKR_ARGUMENTS_BAD " +
                $"(got {ex?.GetType().Name ?? "no exception"}): set " +
                "BouncyHsmBackendFixture.BouncyHsmAcceptsEmptySignature to true and delete this test.");
        }
        finally { key.Destroy(); }
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void NonZeroChaCha20Counter_QuirkStillPresent()
    {
        using var session = _backend.OpenSession();
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure); // raw CKM_CHACHA20 is gated by default
        string label = $"quirk-chacha20-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_CHACHA20)
            .Label(label).Value(RandomNumberGenerator.GetBytes(32)).Encrypt().Decrypt().Build();
        using var key = session.ImportKey(tpl);
#pragma warning disable KLPKCS11009 // raw ChaCha20 is the mechanism under test; the session opts in above
        var counterOne = new Mechanism(CKM.CKM_CHACHA20,
            new CkmChaCha20Params(BitConverter.GetBytes(1u), 32, RandomNumberGenerator.GetBytes(12), 96));
#pragma warning restore KLPKCS11009
        try
        {
            var ex = Record.Exception(() => key.Encrypt(counterOne, "abc"u8));

            Assert.True(ex is Pkcs11Exception { ReturnValue: CKR.CKR_GENERAL_ERROR },
                "harrison314/BouncyHsm#118 looks fixed (a non-zero ChaCha20 block counter no longer gives CKR_GENERAL_ERROR; got " +
                $"{ex?.GetType().Name ?? "no exception"}): set " +
                "BouncyHsmBackendFixture.BouncyHsmAcceptsNonZeroChaCha20Counter to true and delete this test.");
        }
        finally { key.Destroy(); }
    }
}
