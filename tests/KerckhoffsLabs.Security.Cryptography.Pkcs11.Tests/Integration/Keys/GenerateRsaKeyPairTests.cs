using System.Numerics;
using System.Security.Cryptography;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Backend-agnostic assertions for <c>Pkcs11Session.GenerateRsaSigningKeyPair</c>, and for what
/// <c>C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN)</c> makes of a <c>CKA_MODULUS_BITS</c> or
/// <c>CKA_PUBLIC_EXPONENT</c> the library would not send (through the raw dispatch). The per-backend test classes
/// live in <c>GenerateRsaKeyPairTests.&lt;Backend&gt;.cs</c>.
/// </summary>
internal static class GenerateRsaKeyPairTestCases
{
    private static Pkcs11Session OpenSession(IPkcs11Backend backend) =>
        backend.OpenSession();

    internal static void Assert_RejectsTooSmallModulus(IPkcs11Backend backend)
    {
        using var session = OpenSession(backend);
        // A non-positive size is always an argument error.
        Assert.Throws<ArgumentOutOfRangeException>(() => session.GenerateRsaSigningKeyPair(modulusBits: 0));
        // Sub-2048 (NIST SP 800-131A) is refused under Recommended and requires the AllowInsecure policy, not silently produced.
        Assert.Throws<CryptoPolicyViolationException>(() => session.GenerateRsaSigningKeyPair(modulusBits: 1024));
    }

    internal static void Assert_GeneratesRsa2048KeyPair(IPkcs11Backend backend)
    {
        using var session = OpenSession(backend);
        // 2048 keeps the SoftHSM round-trip fast; the production default is 4096.
        using var key = session.GenerateRsaSigningKeyPair(modulusBits: 2048);

        Assert.False(key.PrivateHandle.IsInvalid);
        Assert.False(key.PublicHandle.IsInvalid);
    }

    /// <summary>
    /// A signing pair must not carry <c>CKA_ENCRYPT</c>/<c>CKA_DECRYPT</c> — mixing signing and
    /// key-transport roles on one RSA key pair is unsafe. Use <c>GenerateRsaKeyTransportKeyPair</c>
    /// for a dedicated encryption pair.
    /// </summary>
    internal static void Assert_SigningKeyPair_HasNoEncryptCapability(IPkcs11Backend backend)
    {
        using var session = OpenSession(backend);
        using var key = session.GenerateRsaSigningKeyPair(modulusBits: 2048);

        using var pubAttrs = session.Core.GetAttributeValue(key.PublicHandle, [CKA.CKA_VERIFY, CKA.CKA_ENCRYPT]);
        Assert.True(pubAttrs[0].GetValueAsBool());
        Assert.False(pubAttrs[1].GetValueAsBool());

        using var privAttrs = session.Core.GetAttributeValue(key.PrivateHandle, [CKA.CKA_SIGN, CKA.CKA_DECRYPT]);
        Assert.True(privAttrs[0].GetValueAsBool());
        Assert.False(privAttrs[1].GetValueAsBool());
    }

    /// <summary>
    /// A key-transport pair must not carry <c>CKA_SIGN</c>/<c>CKA_VERIFY</c> and must not carry
    /// <c>CKA_WRAP</c>/<c>CKA_UNWRAP</c> either.
    /// </summary>
    internal static void Assert_GeneratesTransportKeyPair_EncryptDecryptOnly(IPkcs11Backend backend)
    {
        using var session = OpenSession(backend);
        using var key = session.GenerateRsaKeyTransportKeyPair(modulusBits: 2048);

        Assert.False(key.PrivateHandle.IsInvalid);
        Assert.False(key.PublicHandle.IsInvalid);

        using var pubAttrs = session.Core.GetAttributeValue(key.PublicHandle, [CKA.CKA_ENCRYPT, CKA.CKA_VERIFY, CKA.CKA_WRAP]);
        Assert.True(pubAttrs[0].GetValueAsBool());
        Assert.False(pubAttrs[1].GetValueAsBool());
        Assert.False(pubAttrs[2].GetValueAsBool());

        using var privAttrs = session.Core.GetAttributeValue(key.PrivateHandle, [CKA.CKA_DECRYPT, CKA.CKA_SIGN, CKA.CKA_UNWRAP]);
        Assert.True(privAttrs[0].GetValueAsBool());
        Assert.False(privAttrs[1].GetValueAsBool());
        Assert.False(privAttrs[2].GetValueAsBool());
    }

    // === CKA_MODULUS_BITS and CKA_PUBLIC_EXPONENT, through the raw dispatch ==============

    // A refusal of a key size the token cannot make: CKR_ATTRIBUTE_VALUE_INVALID or CKR_TEMPLATE_INCONSISTENT
    // (PKCS#11 v3.2 §4.1, §5.1.6), or CKR_KEY_SIZE_RANGE, which C_GenerateKeyPair does not list but tokens give for
    // a size outside their range (§5.1 leaves room for codes a function does not list).
    private static readonly CKR[] KeyRefusals =
        [CKR.CKR_ATTRIBUTE_VALUE_INVALID, CKR.CKR_TEMPLATE_INCONSISTENT, CKR.CKR_KEY_SIZE_RANGE];

    // C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN) of a session signing pair with the modulus size and exponent (also
    // for the tripwires).
    internal static CKR GenerateRawRsa(IPkcs11Backend backend, Pkcs11SessionCore session, ulong modulusBits, byte[] exponent,
        out ObjectHandle pub, out ObjectHandle priv)
    {
        using var pubClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var privClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var keyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA);
        using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var verify = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var sign = new ObjectAttribute(CKA.CKA_SIGN, true);
        using var sensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var bits = new ObjectAttribute(CKA.CKA_MODULUS_BITS, modulusBits);
        using var publicExponent = new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, exponent);
        using var scope = new MechanismParameterScope();
        CK_MECHANISM mech = new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN).Marshal(scope, out _);
        CK_ATTRIBUTE[] pubTemplate = [.. new[] { pubClass, keyType, token, verify, bits, publicExponent }.Select(a => a.CkAttribute)];
        CK_ATTRIBUTE[] privTemplate = [.. new[] { privClass, keyType, token, sign, sensitive }.Select(a => a.CkAttribute)];
        CKR rv = backend.Library.LowLevelLibrary!.C_GenerateKeyPair((NativeCULong)session.SessionId, in mech, pubTemplate, privTemplate,
            out NativeCULong pubHandle, out NativeCULong privHandle);
        pub = new ObjectHandle((ulong)pubHandle);
        priv = new ObjectHandle((ulong)privHandle);
        return rv;
    }

    private static readonly byte[] F4 = [0x01, 0x00, 0x01];

    public static TheoryData<string> ModulusBitsAboveTheMaximum => ["ulMaxKeySize + 8", "2^32 + 2048"];

    // For CKM_RSA_PKCS_KEY_PAIR_GEN, ulMaxKeySize is the largest modulus in bits (PKCS#11 v3.2 §6.1.4), so a
    // CKA_MODULUS_BITS above it is refused (KeyRefusals), and 2^32 + 2048, where CK_ULONG is 64 bits, never yields
    // a 2048-bit key from a module that narrows it. The first row runs where ulMaxKeySize is at most 8192, so that
    // a module that took it would not keep the run for minutes.
    internal static void Assert_RsaKeyGen_ModulusBitsAboveTheMaximum_IsRefused(IPkcs11Backend backend, string row)
    {
        if (row == "2^32 + 2048")
            Assert.SkipUnless(UnmanagedMemory.NativeULongSize == 8, "CK_ULONG is 32 bits on this platform.");
        backend.RequireMechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
        MechanismInfo info = backend.Library.GetSlotList().First(s => s.SlotId.Value == (ulong)backend.SlotId)
            .GetMechanismInfo(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
        ulong bits = (1UL << 32) + 2048;
        if (row == "ulMaxKeySize + 8")
        {
            Assert.SkipUnless(info.MaxKeySize is > 0 and <= 8192, $"CKM_RSA_PKCS_KEY_PAIR_GEN reports ulMaxKeySize {info.MaxKeySize}.");
            bits = info.MaxKeySize + 8;
        }
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            CKR rv = GenerateRawRsa(backend, session, bits, F4, out ObjectHandle pub, out ObjectHandle priv);
            if (rv == CKR.CKR_OK)
            {
                using var read = session.GetAttributeValue(pub, [CKA.CKA_MODULUS]);
                int length = read[0].GetValueAsByteArray().Length;
                session.DestroyObject(priv);
                session.DestroyObject(pub);
                Assert.Fail($"C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN) with CKA_MODULUS_BITS {bits} (ulMaxKeySize {info.MaxKeySize}) made a {length * 8}-bit key.");
            }
            Assert.True(KeyRefusals.Contains(rv), $"C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN) with CKA_MODULUS_BITS {bits} returned {rv}.");
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    public static TheoryData<string> PublicExponents => ["01 00 03", "2^64 + 65537"];

    // CKA_PUBLIC_EXPONENT is a big integer, most-significant byte first (PKCS#11 v3.2 §4, Table 12), and
    // CKM_RSA_PKCS_KEY_PAIR_GEN copies it from the template, or returns CKR_TEMPLATE_INCONSISTENT "if the
    // implementation cannot use the supplied exponent value" (§6.1.4). So a pair made with 65539 (01 00 03, whose
    // reversal 03 00 01 is another exponent, unlike 65537's) or 2^64 + 65537 (nine bytes, past a 64-bit
    // accumulator) has a public key whose CKA_PUBLIC_EXPONENT reads back as that integer, and a signature the BCL
    // verifies under (n, e); a refusal is CKR_TEMPLATE_INCONSISTENT, and the case then skips for 65539, which a
    // token may simply not offer. It never makes a key with another exponent.
    internal static void Assert_RsaKeyGen_PublicExponent_IsTheOneAsked(IPkcs11Backend backend, string exponentRow)
    {
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_SHA256_RSA_PKCS_PSS);
        byte[] exponent = exponentRow == "01 00 03" ? [0x01, 0x00, 0x03] : [0x01, 0, 0, 0, 0, 0, 0x01, 0x00, 0x01];
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            CKR rv = GenerateRawRsa(backend, session, 2048, exponent, out ObjectHandle pub, out ObjectHandle priv);
            if (rv != CKR.CKR_OK)
            {
                Assert.True(rv == CKR.CKR_TEMPLATE_INCONSISTENT, $"C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN) with CKA_PUBLIC_EXPONENT {exponentRow} returned {rv}.");
                if (exponentRow == "01 00 03")
                    Assert.Skip($"The backend does not take a public exponent of 65539 ({rv}).");
                return;
            }
            try
            {
                using var read = session.GetAttributeValue(pub, [CKA.CKA_MODULUS, CKA.CKA_PUBLIC_EXPONENT]);
                byte[] n = read[0].GetValueAsByteArray();
                byte[] e = read[1].GetValueAsByteArray();
                Assert.True(new BigInteger(exponent, isUnsigned: true, isBigEndian: true) == new BigInteger(e, isUnsigned: true, isBigEndian: true),
                    $"C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN) with CKA_PUBLIC_EXPONENT {Convert.ToHexString(exponent)} made a key whose exponent is {Convert.ToHexString(e)}.");

                byte[] message = "the quick brown fox jumps over the lazy dog"u8.ToArray();
                byte[] signature = session.Sign(
                    new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, new MechanismParams.CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32)),
                    priv, message);
                using var rsa = RSA.Create();
                rsa.ImportParameters(new RSAParameters { Modulus = n, Exponent = e });
                Assert.True(rsa.VerifyData(message, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
                    $"A signature by the key generated with CKA_PUBLIC_EXPONENT {exponentRow} does not verify under the BCL with that exponent.");
            }
            finally { session.DestroyObject(priv); session.DestroyObject(pub); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }
}
