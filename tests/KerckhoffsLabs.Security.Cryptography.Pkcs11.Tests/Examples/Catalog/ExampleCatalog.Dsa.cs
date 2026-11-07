using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

// docs/examples/dsa.md
internal static partial class ExampleCatalog
{
#pragma warning disable KLPKCS11006 // DSAPkcs11, named for coverage
    private static ExampleCase[] DsaCases() =>
    [
        new(Name(nameof(DsaExamples), nameof(DsaExamples.DsaVerifyLegacySignature)), [typeof(DSAPkcs11)],
            [CKM.CKM_DSA_KEY_PAIR_GEN, CKM.CKM_DSA_SHA256], ExampleBackend.SoftHsm2, b => WithSession(b, AssertDsaVerifyLegacySignature)),
        new(Name(nameof(DsaExamples), nameof(DsaExamples.BclDsaVerifyLegacySignature)), [], [], ExampleBackend.SoftHsm2,
            _ =>
            {
                if (OperatingSystem.IsMacOS()) Assert.Skip("macOS's DSA takes only 1024-bit keys.");
                using DSA bcl = DSA.Create(2048);
                byte[] signature = bcl.SignData(Message, HashAlgorithmName.SHA256);
                Assert.True(DsaExamples.BclDsaVerifyLegacySignature(bcl.ExportParameters(false), Message, signature));
                Assert.False(DsaExamples.BclDsaVerifyLegacySignature(bcl.ExportParameters(false), [.. Message, 0], signature));
            }),
    ];
#pragma warning restore KLPKCS11006

    private static void AssertDsaVerifyLegacySignature(Pkcs11Session session)
    {
        // A legacy DSA-2048 key pair on the token (set-up, under AllowInsecure), and a signature it made. The
        // domain parameters are the suite's fixed ones: not every platform's BCL generates 2048-bit DSA.
        using ObjectTemplate publicTemplate = ObjectTemplate.ForPublicKey(CKK.CKK_DSA).Verify()
            .Attribute(CKA.CKA_PRIME, Algorithms.DSAPkcs11TestCases.P)
            .Attribute(CKA.CKA_SUBPRIME, Algorithms.DSAPkcs11TestCases.Q)
            .Attribute(CKA.CKA_BASE, Algorithms.DSAPkcs11TestCases.G).Build();
        using ObjectTemplate privateTemplate = ObjectTemplate.ForPrivateKey(CKK.CKK_DSA).Sign().Build();
        Pkcs11Key key;
        byte[] signature;
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
#pragma warning disable KLPKCS11009, KLPKCS11006 // DSA key generation and signing are the set-up
            key = session.GenerateKeyPair(new Mechanism(CKM.CKM_DSA_KEY_PAIR_GEN), publicTemplate, privateTemplate);
            using var signer = new DSAPkcs11(key);
            signature = signer.SignData(Message, HashAlgorithmName.SHA256);
        }
        using (key)
        {
            Assert.True(DsaExamples.DsaVerifyLegacySignature(session, key, Message, signature));
            Assert.False(DsaExamples.DsaVerifyLegacySignature(session, key, [.. Message, 0], signature));
            using var unleased = new DSAPkcs11(key);
#pragma warning restore KLPKCS11009, KLPKCS11006
            Assert.Throws<CryptoPolicyViolationException>(() => unleased.VerifyData(Message, signature, HashAlgorithmName.SHA256));

            // The BCL tab verifies the same signature from the key's public parameters.
            if (OperatingSystem.IsMacOS()) Assert.Skip("macOS's DSA takes only 1024-bit keys; the token side ran.");
            Assert.True(DsaExamples.BclDsaVerifyLegacySignature(unleased.ExportParameters(false), Message, signature));
        }
    }
}
