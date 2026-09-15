using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// These tests drive gated legacy mechanisms (CKM_SHA_1, CKM_AES_CBC) on purpose — pkcs11-mock's
// dual-function transform is what's under test, not mechanism security — under AllowInsecure, so
// the compile-time warning is suppressed for this file only.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>
/// Coverage for the PKCS#11 dual-function crypto dispatch (<c>C_DigestEncryptUpdate</c>,
/// <c>C_DecryptDigestUpdate</c>, <c>C_DecryptVerifyUpdate</c>) and the "parallel function
/// management" legacy pair (<c>C_GetFunctionStatus</c>, <c>C_CancelFunction</c>) — all previously
/// 0% covered. Unlike the v3.0 message API, pkcs11-mock's implementations of these are real (not
/// stubs): every update function does a deterministic <c>output[i] = input[i] ^ 0xAB</c> transform
/// (verified against vendor/pkcs11-mock/src/pkcs11-mock.c), and C_GetFunctionStatus/C_CancelFunction
/// return the spec-mandated <c>CKR_FUNCTION_NOT_PARALLEL</c> after validating session state. pkcs11-
/// mock's object handles are fixed sentinels (SECRET_KEY=2, PUBLIC_KEY=3, PRIVATE_KEY=4) returned
/// only via C_FindObjects with a matching CKA_CLASS filter — C_GenerateKey/C_CreateObject always
/// return handle 1 (DATA) regardless of template, so these tests locate keys by class instead of
/// generating them.
/// </summary>
[Collection("Mock")]
public sealed class DualFunctionCryptoTests(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    private static byte[] XorAb(byte[] data)
    {
        byte[] result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
            result[i] = (byte)(data[i] ^ 0xAB);
        return result;
    }

    [Fact]
    public void GetFunctionStatus_ReportsFunctionNotParallel()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            var ex = Assert.ThrowsAny<Pkcs11Exception>(() => session.GetFunctionStatus());
            Assert.Equal(CKR.CKR_FUNCTION_NOT_PARALLEL, ex.ReturnValue);
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.CloseSession();
        }
    }

    [Fact]
    public void CancelFunction_ReportsFunctionNotParallel()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            var ex = Assert.ThrowsAny<Pkcs11Exception>(() => session.CancelFunction());
            Assert.Equal(CKR.CKR_FUNCTION_NOT_PARALLEL, ex.ReturnValue);
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.CloseSession();
        }
    }

    [Fact]
    public void DigestEncrypt_XorsPlaintextWithAB()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            using var findClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            ObjectHandle key = Assert.Single(session.FindAllObjects([findClass]));

            session.AllowInsecure = true; // CKM_SHA_1 and CKM_AES_CBC are both gated by default
            var digestMechanism = new Mechanism(CKM.CKM_SHA_1);
            var encryptMechanism = new Mechanism(CKM.CKM_AES_CBC, new byte[16]);
            byte[] plaintext = "dual-function encrypt"u8.ToArray();

            session.DigestEncrypt(digestMechanism, encryptMechanism, key, plaintext, out byte[] digest, out byte[] encrypted);

            Assert.Equal(XorAb(plaintext), encrypted);
            Assert.NotEmpty(digest);
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.CloseSession();
        }
    }

    [Fact]
    public void DecryptDigest_XorsCiphertextWithAB()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            using var findClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            ObjectHandle key = Assert.Single(session.FindAllObjects([findClass]));

            session.AllowInsecure = true;
            var digestMechanism = new Mechanism(CKM.CKM_SHA_1);
            var decryptMechanism = new Mechanism(CKM.CKM_AES_CBC, new byte[16]);
            byte[] ciphertext = "dual-function decrypt"u8.ToArray();

            session.DecryptDigest(digestMechanism, decryptMechanism, key, ciphertext, out byte[] digest, out byte[] decrypted);

            Assert.Equal(XorAb(ciphertext), decrypted);
            Assert.NotEmpty(digest);
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.CloseSession();
        }
    }

    [Fact]
    public void DecryptVerify_XorsCiphertextWithAB_AndValidatesTheCannedSignature()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            using var findSecret = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            ObjectHandle secretKey = Assert.Single(session.FindAllObjects([findSecret]));
            using var findPublic = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
            ObjectHandle publicKey = Assert.Single(session.FindAllObjects([findPublic]));

            session.AllowInsecure = true;
            // pkcs11-mock's C_VerifyInit only recognizes CKM_RSA_PKCS/CKM_SHA1_RSA_PKCS.
            var verificationMechanism = new Mechanism(CKM.CKM_SHA1_RSA_PKCS);
            var decryptionMechanism = new Mechanism(CKM.CKM_AES_CBC, new byte[16]);
            byte[] ciphertext = "dual-function decrypt+verify"u8.ToArray();
            // pkcs11-mock's C_VerifyFinal only accepts this exact 10-byte canned signature.
            byte[] signature = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];

            session.DecryptVerify(verificationMechanism, publicKey, decryptionMechanism, secretKey,
                ciphertext, signature, out byte[] decryptedData, out bool isValid);

            Assert.True(isValid);
            Assert.Equal(XorAb(ciphertext), decryptedData);
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.CloseSession();
        }
    }
}
