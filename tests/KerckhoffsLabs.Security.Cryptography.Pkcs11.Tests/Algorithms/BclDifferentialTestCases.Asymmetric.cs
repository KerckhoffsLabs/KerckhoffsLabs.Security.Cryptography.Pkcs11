using System.Security.Cryptography;
using CsCheck;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.PropertyBased;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms.PropertyTestSupport;

// SlhDsa is an evaluation-only BCL API (SYSLIB5006); the SLH-DSA property verifies with it.
#pragma warning disable SYSLIB5006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// The randomized algorithms. A signature or an OAEP ciphertext has no single right value, so the BCL is
// the oracle the other way: it must accept what the token produces from the token's exported public key,
// and the token must open what the BCL produces for it. Each property generates one key pair on the token
// and draws the messages, contexts and KDF inputs; ECDH draws a fresh BCL peer for each case.
//
// ML-KEM has no differential property: its only input is the token's key, so a generator would have
// nothing to vary. MLKemPkcs11TestCases decapsulates a BCL encapsulation, and AlgorithmLawTestCases checks
// decapsulation against the token's own encapsulations, tampered ones included.
internal static partial class BclDifferentialTestCases
{
    // === RSA ===============================================================================

    // The token's PKCS#1 v1.5 or PSS signature over any message verifies under the BCL; emptyData false
    // leaves the empty message out, for a token that refuses to sign it.
    internal static void Assert_RsaSignData_VerifiesWithBcl(IPkcs11Backend backend, string padding, string hashName, bool emptyData = true)
    {
        var hash = new HashAlgorithmName(hashName);
        RSASignaturePadding signaturePadding = SignaturePadding(padding);
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, RsaSignMechanism(hashName, padding));
        RequireHost(Hash(hashName).HostSupportsHash(), $"Host BCL has no {hashName}.");

        WithRsa(backend, rsa =>
        {
            using var bcl = RSA.Create();
            bcl.ImportParameters(rsa.ExportParameters(includePrivateParameters: false));

            CsInputs.Check(CsInputs.Bytes(emptyData ? 0 : 1, 2048), data =>
                Assert.True(bcl.VerifyData(data, rsa.SignData(data, hash, signaturePadding), hash, signaturePadding)));
        });
    }

    // The token decrypts any OAEP ciphertext the BCL makes for its public key, for every message length
    // the key and hash allow.
    internal static void Assert_RsaOaep_DecryptsBclCiphertext(IPkcs11Backend backend, string hashName)
    {
        var hash = new HashAlgorithmName(hashName);
        RSAEncryptionPadding padding = RSAEncryptionPadding.CreateOaep(hash);
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_RSA_PKCS_OAEP);
        RequireHost(Hash(hashName).HostSupportsHash(), $"Host BCL has no {hashName}.");

        WithRsa(backend, rsa =>
        {
            using var bcl = RSA.Create();
            bcl.ImportParameters(rsa.ExportParameters(includePrivateParameters: false));
            int maxLength = (bcl.KeySize / 8) - (2 * Hash(hashName).Size) - 2;

            RequireOaepHash(() => rsa.Decrypt(bcl.Encrypt([1], padding), padding));

            CsInputs.Check(CsInputs.Bytes(0, maxLength), data =>
                Assert.Equal(data, rsa.Decrypt(bcl.Encrypt(data, padding), padding)));
        });
    }

    // === EC ================================================================================

    // The token's signature over any message, in either encoding, and over its digest verifies under the BCL.
    internal static void Assert_EcdsaSignData_VerifiesWithBcl(IPkcs11Backend backend, string curve, DSASignatureFormat format)
    {
        backend.RequireMechanisms(CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA);
        var (_, hash) = EcSpec(curve);

        using var session = backend.OpenSession();
        WithEcKey(backend, session, curve, derive: false, key =>
        {
            using var ecdsa = new ECDsaPkcs11(key);
            using var bcl = ECDsa.Create(ecdsa.ExportParameters(includePrivateParameters: false));

            CsInputs.Check(CsInputs.Bytes(0, 2048), data =>
            {
                Assert.True(bcl.VerifyData(data, ecdsa.SignData(data, hash, format), hash, format));

                byte[] digest = Hash(hash.Name!).Hash(data);
                Assert.True(bcl.VerifyHash(digest, ecdsa.SignHash(digest, format), format));
            });
        });
    }

    private sealed record EcdhCase(string Hash, byte[] Prepend, byte[] Append, byte[] HmacKey)
    {
        public override string ToString() =>
            $"{Hash}, prepend {Convert.ToHexString(Prepend)}, append {Convert.ToHexString(Append)}, hmac key {Convert.ToHexString(HmacKey)}";
    }

    // The token and a fresh BCL peer agree on the raw secret and on every KDF the adapter offers, with any
    // prepend, append and HMAC key (empty for none).
    internal static void Assert_Ecdh_AgreesWithBcl(IPkcs11Backend backend, string curve)
    {
        backend.RequireMechanisms(CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDH1_DERIVE);
        var (bclCurve, _) = EcSpec(curve);
        var inputs =
            from hash in Gen.OneOfConst("SHA256", "SHA384", "SHA512")
            from prepend in CsInputs.Bytes(0, 32)
            from append in CsInputs.Bytes(0, 32)
            from hmacKey in CsInputs.Bytes(0, 64)
            select new EcdhCase(hash, prepend, append, hmacKey);

        using var session = backend.OpenSession();
        WithEcKey(backend, session, curve, derive: true, key =>
        {
            // Every ECDiffieHellman method returns the agreement as bytes, which the default policy refuses.
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            using var alice = new ECDiffieHellmanPkcs11(key);

            CsInputs.Check(inputs, input =>
            {
                using var bob = ECDiffieHellman.Create(bclCurve);
                var hash = new HashAlgorithmName(input.Hash);
                byte[]? hmacKey = input.HmacKey.Length == 0 ? null : input.HmacKey;

                Assert.Equal(bob.DeriveRawSecretAgreement(alice.PublicKey), alice.DeriveRawSecretAgreement(bob.PublicKey));
                Assert.Equal(
                    bob.DeriveKeyFromHash(alice.PublicKey, hash, input.Prepend, input.Append),
                    alice.DeriveKeyFromHash(bob.PublicKey, hash, input.Prepend, input.Append));
                Assert.Equal(
                    bob.DeriveKeyFromHmac(alice.PublicKey, hash, hmacKey, input.Prepend, input.Append),
                    alice.DeriveKeyFromHmac(bob.PublicKey, hash, hmacKey, input.Prepend, input.Append));
            });
        });
    }

    // === Post-quantum signatures ===========================================================

    // A context of up to 255 bytes, the most FIPS 204 and FIPS 205 allow; empty only on a token that
    // refuses a context.
    private static Gen<byte[]> PqcContext(IPkcs11Backend backend) =>
        backend.SupportsPqcSignContext ? CsInputs.Bytes(0, 255) : CsInputs.Bytes(0);

    // The token's ML-DSA signature over any message, under any context, verifies under the BCL; emptyData
    // false leaves the empty message out, for a token that refuses to sign it.
    internal static void Assert_MlDsaSignData_VerifiesWithBcl(IPkcs11Backend backend, CkpMlDsa parameterSet, bool emptyData = true)
    {
        Assert.SkipUnless(backend.SupportsMlDsa, "Backend cannot operate ML-DSA (CKM_ML_DSA unavailable).");
        RequireHost(MLDsa.IsSupported, "Host BCL cannot operate ML-DSA (needs OpenSSL 3.5+ or a recent Windows).");
        var inputs =
            from data in CsInputs.Bytes(emptyData ? 0 : 1, 1024)
            from context in PqcContext(backend)
            select (data, context);

        WithPqcKey(backend, CKK.CKK_ML_DSA, CKM.CKM_ML_DSA_KEY_PAIR_GEN, (ulong)parameterSet, (_, key) =>
        {
            using var mldsa = new MLDsaPkcs11(key);
            using var bcl = MLDsa.ImportMLDsaPublicKey(mldsa.Algorithm, mldsa.ExportMLDsaPublicKey());

            CsInputs.Check(inputs, input =>
                Assert.True(bcl.VerifyData(input.data, mldsa.SignData(input.data, input.context), input.context)));
        });
    }

    // The same for SLH-DSA, on the parameter set the backend tests (signing is slow, so one set).
    internal static void Assert_SlhDsaSignData_VerifiesWithBcl(IPkcs11Backend backend, bool emptyData = true)
    {
        Assert.SkipUnless(backend.SupportsSlhDsa, "Backend cannot operate SLH-DSA (CKM_SLH_DSA unavailable).");
        RequireHost(SlhDsa.IsSupported, "Host BCL cannot operate SLH-DSA (needs OpenSSL 3.5+ or a recent Windows).");
        var inputs =
            from data in CsInputs.Bytes(emptyData ? 0 : 1, 1024)
            from context in PqcContext(backend)
            select (data, context);

        WithPqcKey(backend, CKK.CKK_SLH_DSA, CKM.CKM_SLH_DSA_KEY_PAIR_GEN, (ulong)backend.SlhDsaTestParameterSet, (_, key) =>
        {
            using var slhdsa = new SlhDsaPkcs11(key);
            using var bcl = SlhDsa.ImportSlhDsaPublicKey(slhdsa.Algorithm, slhdsa.ExportSlhDsaPublicKey());

            CsInputs.Check(inputs, input =>
                Assert.True(bcl.VerifyData(input.data, slhdsa.SignData(input.data, input.context), input.context)));
        });
    }
}
