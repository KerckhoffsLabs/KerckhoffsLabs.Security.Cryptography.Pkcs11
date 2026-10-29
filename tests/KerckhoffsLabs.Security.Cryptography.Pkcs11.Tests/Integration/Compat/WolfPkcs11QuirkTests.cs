using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Compat;

/// <summary>
/// One test per gate on <see cref="WolfPkcs11BackendFixture"/>: each reproduces a known wolfPKCS11 bug
/// directly and asserts that it is still there. When a submodule bump brings the upstream fix, the
/// matching test fails, telling us to remove the gate so the shared test cases run again.
/// </summary>
[Collection("WolfPkcs11")]
public sealed class WolfPkcs11QuirkTests(WolfPkcs11BackendFixture backend)
{
    private readonly IPkcs11Backend _backend = backend;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void DerivedKeySensitivity_QuirkStillPresent()
    {
        using var session = _backend.OpenSession();
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        Exception? ex = null;
        PropertyTestSupport.WithEcKey(_backend, session, "P-256", derive: true, aliceKey =>
            PropertyTestSupport.WithEcKey(_backend, session, "P-256", derive: true, bobKey =>
            {
                using var alice = new ECDiffieHellmanPkcs11(aliceKey);
                using var bob = new ECDiffieHellmanPkcs11(bobKey);
                ex = Record.Exception(() => alice.DeriveRawSecretAgreement(bob.PublicKey));
            }));

        Assert.True(ex is Pkcs11Exception { ReturnValue: CKR.CKR_ATTRIBUTE_SENSITIVE },
            "The raw ECDH secret derived from a sensitive key with a CKA_SENSITIVE=false template is now readable " +
            $"(got {ex?.GetType().Name ?? "no exception"}): set " +
            "WolfPkcs11BackendFixture.WolfPkcs11DerivedKeysTakeTheTemplatesSensitivity to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void EmptyOaepMessage_QuirkStillPresent()
    {
        Exception? ex = null;
        PropertyTestSupport.WithRsa(_backend, rsa => ex = Record.Exception(() => rsa.Encrypt([], RSAEncryptionPadding.OaepSHA256)));

        Assert.True(ex is Pkcs11Exception { ReturnValue: CKR.CKR_FUNCTION_FAILED },
            "RSA-OAEP encryption of an empty message no longer gives CKR_FUNCTION_FAILED " +
            $"(got {(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name ?? "no exception"}): set " +
            "WolfPkcs11BackendFixture.WolfPkcs11AcceptsEmptyOaepMessage to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void MalformedSignature_QuirkStillPresent()
    {
        byte[] data = Encoding.UTF8.GetBytes("malformed signature");
        var failures = new List<string>();

        // RSA PKCS#1 v1.5, its last bit flipped.
        PropertyTestSupport.WithRsa(_backend, rsa =>
        {
            byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            signature[^1] ^= 0x01;
            failures.Add(Code(() => rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), "RSA PKCS#1 v1.5"));
        });

        // ECDSA P-521, r with its top bit set: above the 521-bit order.
        using (var session = _backend.OpenSession())
        {
            PropertyTestSupport.WithEcKey(_backend, session, "P-521", derive: false, key =>
            {
                using var ecdsa = new ECDsaPkcs11(key);
                byte[] signature = ecdsa.SignData(data, HashAlgorithmName.SHA512, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                signature[0] |= 0x80;
                failures.Add(Code(() => ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA512, DSASignatureFormat.IeeeP1363FixedFieldConcatenation), "ECDSA P-521"));
            });
        }

        // ML-DSA-44, its last hint count past omega (80), which FIPS 204's HintBitUnpack rejects.
        PropertyTestSupport.WithPqcKey(_backend, CKK.CKK_ML_DSA, CKM.CKM_ML_DSA_KEY_PAIR_GEN, (ulong)CkpMlDsa.CKP_ML_DSA_44, (_, key) =>
        {
            using var mldsa = new MLDsaPkcs11(key);
            byte[] signature = mldsa.SignData(data);
            signature[^1] = 0xFF;
            failures.Add(Code(() => mldsa.VerifyData(data, signature), "ML-DSA-44"));
        });

        Assert.True(failures.TrueForAll(f => f.EndsWith(": CKR_FUNCTION_FAILED", StringComparison.Ordinal)),
            $"A malformed signature no longer gives CKR_FUNCTION_FAILED everywhere ({string.Join("; ", failures)}): " +
            "set WolfPkcs11BackendFixture.WolfPkcs11RejectsMalformedSignatures to true and delete this test, or split the " +
            "flag if only some are fixed.");
    }

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void WrongLengthRsaSignature_QuirkStillPresent()
    {
        Exception? ex = null;
        PropertyTestSupport.WithRsa(_backend, rsa =>
        {
            byte[] data = Encoding.UTF8.GetBytes("wrong length");
            byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            ex = Record.Exception(() => rsa.VerifyData(data, signature[..^1], HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        });

        Assert.True(ex is Pkcs11Exception { ReturnValue: CKR.CKR_FUNCTION_FAILED },
            "C_Verify of an RSA signature one byte short no longer gives CKR_FUNCTION_FAILED " +
            $"(got {(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name ?? "no exception"}): set " +
            "WolfPkcs11BackendFixture.WolfPkcs11RejectsWrongLengthRsaSignatures to true and delete this test.");
    }

    private static string Code(Func<bool> verify, string what)
    {
        Exception? ex = Record.Exception(() => verify());
        return $"{what}: {(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name ?? "returned"}";
    }

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void MinimumRsaKeySize_QuirkStillPresent()
    {
        using var session = _backend.OpenSession();
        Pkcs11Slot slot = _backend.Library.GetSlotList().First(s => s.SlotId.Value == (ulong)_backend.SlotId);
        ulong minimum = slot.GetMechanismInfo(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN).MinKeySize;
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Verify().ModulusBits((int)minimum).PublicExponent([0x01, 0x00, 0x01]).OnToken(false).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA).Sign().OnToken(false).Build();

        var ex = Record.Exception(() => session.GenerateKeyPair(new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), pubTpl, privTpl).Dispose());

        Assert.True(minimum < 2048 && ex is Pkcs11Exception { ReturnValue: CKR.CKR_FUNCTION_FAILED },
            $"CKM_RSA_PKCS_KEY_PAIR_GEN now generates the {minimum}-bit minimum it advertises, or advertises 2048 or more " +
            $"(got {(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name ?? "no exception"}): set " +
            "WolfPkcs11BackendFixture.WolfPkcs11GeneratesItsMinimumRsaKeySize to true and delete this test.");
    }
}
