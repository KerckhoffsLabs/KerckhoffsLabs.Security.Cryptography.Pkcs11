using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>
/// Backend-agnostic tests of the token's combined SHA-3 signing mechanisms (<c>CKM_ECDSA_SHA3_256</c>,
/// <c>CKM_SHA3_256_RSA_PKCS_PSS</c> with <c>CKG_MGF1_SHA3_256</c>): the token signs, and the BCL verifies
/// with its own SHA-3 against the exported public key. These go through <see cref="Pkcs11Key.Sign"/>, so that
/// they test the token's combined mechanisms themselves, whichever path a signing adapter takes.
/// </summary>
internal static class Sha3SignatureTestCases
{
    private static readonly byte[] Message = "SHA-3 signed on the token, verified by the BCL"u8.ToArray();

    internal static void Assert_EcdsaSha3_256_VerifiesUnderBcl(IPkcs11Backend backend)
    {
        RequireBclSha3();
        backend.RequireMechanisms(CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA_SHA3_256);
        using var session = backend.OpenSession();
        using var key = session.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        try
        {
            byte[] signature = key.Sign(new Mechanism(CKM.CKM_ECDSA_SHA3_256), Message);

            using var adapter = new ECDsaPkcs11(key);
            using var bcl = ECDsa.Create(adapter.ExportParameters(includePrivateParameters: false));
            Assert.True(bcl.VerifyData(Message, signature, HashAlgorithmName.SHA3_256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
            Assert.False(bcl.VerifyData(Tampered(Message), signature, HashAlgorithmName.SHA3_256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        }
        finally { key.Destroy(); }
    }

    internal static void Assert_RsaPssSha3_256_VerifiesUnderBcl(IPkcs11Backend backend)
    {
        RequireBclSha3();
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_SHA3_256_RSA_PKCS_PSS);
        using var session = backend.OpenSession();
        using var key = session.GenerateRsaSigningKeyPair(2048);
        try
        {
            // Salt as long as the hash, which is what the BCL's PSS verification expects.
            var pss = new Mechanism(CKM.CKM_SHA3_256_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA3_256, CKG.CKG_MGF1_SHA3_256, 32));
            byte[] signature = key.Sign(pss, Message);

            using var adapter = new RSAPkcs11(key);
            using var bcl = RSA.Create(adapter.ExportParameters(includePrivateParameters: false));
            Assert.True(bcl.VerifyData(Message, signature, HashAlgorithmName.SHA3_256, RSASignaturePadding.Pss));
            Assert.False(bcl.VerifyData(Tampered(Message), signature, HashAlgorithmName.SHA3_256, RSASignaturePadding.Pss));
        }
        finally { key.Destroy(); }
    }

    private static void RequireBclSha3() =>
        Assert.SkipUnless(SHA3_256.IsSupported, "The host BCL has no SHA3-256 to verify with.");

    private static byte[] Tampered(byte[] data)
    {
        byte[] copy = [.. data];
        copy[0] ^= 0x01;
        return copy;
    }
}
