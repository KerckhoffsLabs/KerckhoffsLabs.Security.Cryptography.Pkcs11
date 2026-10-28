using System.Security.Cryptography;
using FsCheck;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.PropertyBased;
using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms.PropertyTestSupport;

// SlhDsaPkcs11 derives from an evaluation-only BCL API (SYSLIB5006).
#pragma warning disable SYSLIB5006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// The asymmetric laws, on keys the token generates (one key pair per theory row): the token verifies its
// own signature and no other, opens its own OAEP ciphertext, agrees with itself on an ECDH secret, and
// decapsulates its own ML-KEM encapsulation, rejecting a tampered one implicitly (FIPS 203: a different
// secret, no error). Messages are never empty here, so each one has a bit to flip; the differential
// properties cover the empty message.
internal static partial class AlgorithmLawTestCases
{
    // === Signatures ========================================================================

    // The token's signature over the message verifies on the token; with one bit of the message or of
    // the signature flipped it does not, and verification returns false rather than throwing.
    private static void AssertSignatureLaws(Func<byte[], byte[]> sign, Func<byte[], byte[], bool> verify, Arbitrary<byte[]> messages)
    {
        FsInputs.Check(messages, FsInputs.BitIndex(), FsInputs.BitIndex(), (message, messageBit, signatureBit) =>
        {
            byte[] signature = sign(message);

            Assert.True(verify(message, signature), "The token rejected its own signature.");
            Assert.False(verify(FsInputs.FlipBit(message, messageBit), signature), "The signature verified over a message with one bit flipped.");
            Assert.False(verify(message, FsInputs.FlipBit(signature, signatureBit)), "A signature with one bit flipped verified.");
        });
    }

    internal static void Assert_RsaSignature_VerifiesOnlyUnaltered(IPkcs11Backend backend, string padding, string hashName)
    {
        var hash = new HashAlgorithmName(hashName);
        RSASignaturePadding signaturePadding = SignaturePadding(padding);
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, RsaSignMechanism(hashName, padding));

        WithRsa(backend, rsa => AssertSignatureLaws(
            message => rsa.SignData(message, hash, signaturePadding),
            (message, signature) => rsa.VerifyData(message, signature, hash, signaturePadding),
            FsInputs.Bytes(1, 2048)));
    }

    internal static void Assert_EcdsaSignature_VerifiesOnlyUnaltered(IPkcs11Backend backend, string curve, DSASignatureFormat format)
    {
        backend.RequireMechanisms(CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA);
        var (_, hash) = EcSpec(curve);

        using var session = backend.OpenSession();
        WithEcKey(backend, session, curve, derive: false, key =>
        {
            using var ecdsa = new ECDsaPkcs11(key);
            AssertSignatureLaws(
                message => ecdsa.SignData(message, hash, format),
                (message, signature) => ecdsa.VerifyData(message, signature, hash, format),
                FsInputs.Bytes(1, 2048));
        });
    }

    // Under a context of up to 255 bytes, or none on a token that refuses one.
    internal static void Assert_MlDsaSignature_VerifiesOnlyUnaltered(IPkcs11Backend backend, CkpMlDsa parameterSet)
    {
        Assert.SkipUnless(backend.SupportsMlDsa, "Backend cannot operate ML-DSA (CKM_ML_DSA unavailable).");

        WithPqcKey(backend, CKK.CKK_ML_DSA, CKM.CKM_ML_DSA_KEY_PAIR_GEN, (ulong)parameterSet, (_, key) =>
        {
            using var mldsa = new MLDsaPkcs11(key);
            AssertContextSignatureLaws(backend, mldsa.SignData, mldsa.VerifyData);
        });
    }

    // On the parameter set the backend tests (signing is slow, so one set).
    internal static void Assert_SlhDsaSignature_VerifiesOnlyUnaltered(IPkcs11Backend backend)
    {
        Assert.SkipUnless(backend.SupportsSlhDsa, "Backend cannot operate SLH-DSA (CKM_SLH_DSA unavailable).");

        WithPqcKey(backend, CKK.CKK_SLH_DSA, CKM.CKM_SLH_DSA_KEY_PAIR_GEN, (ulong)backend.SlhDsaTestParameterSet, (_, key) =>
        {
            using var slhdsa = new SlhDsaPkcs11(key);
            AssertContextSignatureLaws(backend, slhdsa.SignData, slhdsa.VerifyData);
        });
    }

    private static void AssertContextSignatureLaws(
        IPkcs11Backend backend, Func<byte[], byte[]?, byte[]> sign, Func<byte[], byte[], byte[]?, bool> verify)
    {
        Arbitrary<byte[]> contexts = backend.SupportsPqcSignContext ? FsInputs.Bytes(0, 255) : FsInputs.Bytes(0, 0);
        FsInputs.Check(FsInputs.Zip(FsInputs.Bytes(1, 1024), contexts), FsInputs.BitIndex(), FsInputs.BitIndex(), (input, messageBit, signatureBit) =>
        {
            var (message, context) = input;
            byte[] signature = sign(message, context);

            Assert.True(verify(message, signature, context), "The token rejected its own signature.");
            Assert.False(verify(FsInputs.FlipBit(message, messageBit), signature, context), "The signature verified over a message with one bit flipped.");
            Assert.False(verify(message, FsInputs.FlipBit(signature, signatureBit), context), "A signature with one bit flipped verified.");
        });
    }

    // === RSA-OAEP ==========================================================================

    // The token opens its own OAEP ciphertext, for every message length the key and hash allow; emptyData
    // false leaves the empty message out, for a token that does not encrypt it.
    internal static void Assert_RsaOaep_OpensWhatItSeals(IPkcs11Backend backend, string hashName, bool emptyData = true)
    {
        RSAEncryptionPadding padding = RSAEncryptionPadding.CreateOaep(new HashAlgorithmName(hashName));
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_RSA_PKCS_OAEP);

        WithRsa(backend, rsa =>
        {
            RequireOaepHash(() => rsa.Decrypt(rsa.Encrypt([1], padding), padding));

            FsInputs.Check(FsInputs.Bytes(emptyData ? 0 : 1, OaepMaxLength(rsa, hashName)), message =>
                Assert.Equal(message, rsa.Decrypt(rsa.Encrypt(message, padding), padding)));
        });
    }

    // === ECDH ==============================================================================

    // Two key pairs on the token agree on the raw secret and on the hashed one, with any prepend and
    // append, whichever side derives.
    internal static void Assert_Ecdh_TokenKeysAgree(IPkcs11Backend backend, string curve)
    {
        backend.RequireMechanisms(CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDH1_DERIVE);

        using var session = backend.OpenSession();
        // Every ECDiffieHellman method returns the agreement as bytes, which the default policy refuses.
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        WithEcKey(backend, session, curve, derive: true, aliceKey =>
            WithEcKey(backend, session, curve, derive: true, bobKey =>
            {
                using var alice = new ECDiffieHellmanPkcs11(aliceKey);
                using var bob = new ECDiffieHellmanPkcs11(bobKey);
                Assert.Equal(alice.DeriveRawSecretAgreement(bob.PublicKey), bob.DeriveRawSecretAgreement(alice.PublicKey));

                FsInputs.Check(FsInputs.OneOf("SHA256", "SHA384", "SHA512"), FsInputs.Bytes(0, 32), FsInputs.Bytes(0, 32), (hashName, prepend, append) =>
                {
                    var hash = new HashAlgorithmName(hashName);
                    Assert.Equal(
                        alice.DeriveKeyFromHash(bob.PublicKey, hash, prepend, append),
                        bob.DeriveKeyFromHash(alice.PublicKey, hash, prepend, append));
                });
            }));
    }

    // === ML-KEM ============================================================================

    // The token decapsulates its own encapsulation to the shared secret it encapsulated, and a ciphertext
    // with one bit flipped to a different secret, without an error (FIPS 203 implicit rejection).
    internal static void Assert_MlKem_DecapsulatesItsOwn_RejectsAnyBitFlipImplicitly(IPkcs11Backend backend, CkpMlKem parameterSet)
    {
        backend.RequireMlKemParameterSet(EncapsulationKeySize(parameterSet));

        WithPqcKey(backend, CKK.CKK_ML_KEM, CKM.CKM_ML_KEM_KEY_PAIR_GEN, (ulong)parameterSet, (session, key) =>
        {
            // Encapsulate and Decapsulate return the shared secret as bytes, which the default policy refuses.
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            using var mlkem = new MLKemPkcs11(key);

            FsInputs.Check(FsInputs.BitIndex(), bit =>
            {
                mlkem.Encapsulate(out byte[] ciphertext, out byte[] sharedSecret);

                Assert.Equal(sharedSecret, mlkem.Decapsulate(ciphertext));
                Assert.NotEqual(sharedSecret, mlkem.Decapsulate(FsInputs.FlipBit(ciphertext, bit)));
            });
        });
    }

    private static int EncapsulationKeySize(CkpMlKem parameterSet) => parameterSet switch
    {
        CkpMlKem.CKP_ML_KEM_512 => MLKemAlgorithm.MLKem512.EncapsulationKeySizeInBytes,
        CkpMlKem.CKP_ML_KEM_768 => MLKemAlgorithm.MLKem768.EncapsulationKeySizeInBytes,
        CkpMlKem.CKP_ML_KEM_1024 => MLKemAlgorithm.MLKem1024.EncapsulationKeySizeInBytes,
        _ => throw new ArgumentOutOfRangeException(nameof(parameterSet), parameterSet, "Unexpected ML-KEM parameter set."),
    };
}
