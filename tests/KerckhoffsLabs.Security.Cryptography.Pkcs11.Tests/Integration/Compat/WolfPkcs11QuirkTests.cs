using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
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

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void WrapTemplate_QuirkStillPresent()
    {
        using var session = _backend.OpenSession();

        var ex = Record.Exception(() => session.GenerateAesKeyEncryptionKey().Dispose());

        Assert.True(ex is Pkcs11Exception { ReturnValue: CKR.CKR_ATTRIBUTE_VALUE_INVALID },
            "C_GenerateKey with CKA_WRAP_TEMPLATE and CKA_UNWRAP_TEMPLATE no longer gives CKR_ATTRIBUTE_VALUE_INVALID " +
            $"(got {(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name ?? "no exception"}): set " +
            "WolfPkcs11BackendFixture.WolfPkcs11AcceptsWrapTemplates to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void EcPrivateKeyUnwrap_StillMissing()
    {
        using var session = _backend.OpenSession();
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        byte[] rawKek = RandomNumberGenerator.GetBytes(32);
        ObjectHandle kekHandle = TestKeys.ImportAesWrappingKey(session.Core, rawKek);
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var aes = Aes.Create();
        aes.Key = rawKek;
        byte[] iv = RandomNumberGenerator.GetBytes(16);
        byte[] wrapped = aes.EncryptCbc(ec.ExportPkcs8PrivateKey(), iv, PaddingMode.PKCS7);
        using var cls = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var type = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC);
        using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var sign = new ObjectAttribute(CKA.CKA_SIGN, true);

#pragma warning disable KLPKCS11009 // CBC-PAD is the private-key wrap every backend offers.
        var ex = Record.Exception(() => session.Core.UnwrapKey(new Mechanism(CKM.CKM_AES_CBC_PAD, iv), kekHandle, wrapped, [cls, type, token, sign]));
#pragma warning restore KLPKCS11009
        session.Core.DestroyObject(kekHandle);

        Assert.True(ex is Pkcs11Exception { ReturnValue: CKR.CKR_KEY_NOT_WRAPPABLE },
            "C_UnwrapKey of an EC private key no longer gives CKR_KEY_NOT_WRAPPABLE " +
            $"(got {(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name ?? "no exception"}): set " +
            "WolfPkcs11BackendFixture.WolfPkcs11UnwrapsEcPrivateKeys to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void SessionObjectVisibility_QuirkStillPresent()
    {
        using var other = TestKeys.OpenLoggedInSession(_backend);
        using var creator = _backend.Library.GetSlotList().First(s => s.SlotId.Value == (ulong)_backend.SlotId).OpenSessionCore();
        string label = $"kl-visibility-{Guid.NewGuid():N}";
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
        creator.CreateObject([attrClass, attrToken, attrLabel]);

        int seen = other.FindAllObjects([attrClass, attrLabel]).Count;
        TestKeys.LogoutIfRequired(_backend, other);

        Assert.True(seen == 0,
            "Another session of the application now sees a session object: set " +
            "WolfPkcs11BackendFixture.WolfPkcs11SharesSessionObjectsAcrossSessions to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void MultipartSignAndEcb_QuirkStillPresent()
    {
        using var session = TestKeys.OpenLoggedInSession(_backend);
        LowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
        var sid = (NativeCULong)session.SessionId;
        var (pub, priv) = TestKeys.GenerateEcP256KeyPair(session);
        ObjectHandle aes = TestKeys.CreateAes256Key(session, RandomNumberGenerator.GetBytes(32));
        var failures = new List<string>();
        try
        {
            using var scope = new MechanismParameterScope();
            CK_MECHANISM ecdsa = new Mechanism(CKM.CKM_ECDSA_SHA256).Marshal(scope, out _);
            CKR init = lowLevel.C_SignInit(sid, in ecdsa, (NativeCULong)priv.ObjectId);
            failures.Add($"ECDSA-SHA256 C_SignUpdate: {(init == CKR.CKR_OK ? lowLevel.C_SignUpdate(sid, new byte[32]) : init)}");
            if (init == CKR.CKR_OK) lowLevel.C_Sign(sid, new byte[32], new byte[132], lengthOnly: false, out _);
#pragma warning disable KLPKCS11009 // ECB is the mechanism whose multi-part support is checked; raw low-level calls, no policy.
            CK_MECHANISM ecb = new Mechanism(CKM.CKM_AES_ECB).Marshal(scope, out _);
#pragma warning restore KLPKCS11009
            init = lowLevel.C_EncryptInit(sid, in ecb, (NativeCULong)aes.ObjectId);
            failures.Add($"AES-ECB C_EncryptUpdate: {(init == CKR.CKR_OK ? lowLevel.C_EncryptUpdate(sid, new byte[16], new byte[16], lengthOnly: false, out _) : init)}");
        }
        finally
        {
            session.DestroyObject(aes);
            session.DestroyObject(priv);
            session.DestroyObject(pub);
            TestKeys.LogoutIfRequired(_backend, session);
        }

        Assert.True(failures.TrueForAll(f => f.EndsWith(": CKR_MECHANISM_INVALID", StringComparison.Ordinal)),
            $"A multi-part hash-and-sign or AES-ECB operation no longer gives CKR_MECHANISM_INVALID ({string.Join("; ", failures)}): " +
            "set WolfPkcs11BackendFixture.WolfPkcs11DoesMultipartSignAndEcb to true and delete this test, or split the flag " +
            "if only some are fixed.");
    }

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void ShortBufferLength_QuirkStillPresent()
    {
        using var session = TestKeys.OpenLoggedInSession(_backend);
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, $"kl-short-buffer-{Guid.NewGuid():N}");
        ObjectHandle data = session.CreateObject([attrClass, attrToken, attrLabel]);
        IntPtr buffer = System.Runtime.InteropServices.Marshal.AllocHGlobal(64);
        CKR rv;
        ulong length;
        try
        {
            CK_ATTRIBUTE[] template = [new CK_ATTRIBUTE { type = (NativeCULong)(ulong)CKA.CKA_LABEL, value = buffer, valueLen = (NativeCULong)1UL }];
            rv = _backend.Library.LowLevelLibrary!.C_GetAttributeValue((NativeCULong)session.SessionId, (NativeCULong)data.ObjectId, template);
            length = (ulong)template[0].valueLen;
        }
        finally
        {
            System.Runtime.InteropServices.Marshal.FreeHGlobal(buffer);
            session.DestroyObject(data);
            TestKeys.LogoutIfRequired(_backend, session);
        }

        Assert.True(rv == CKR.CKR_BUFFER_TOO_SMALL && length == 1,
            $"C_GetAttributeValue into a 1-byte buffer now gives {rv} with ulValueLen {length}: set " +
            "WolfPkcs11BackendFixture.WolfPkcs11MarksAShortBufferUnavailable to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void PrivateKeyOfASecretKeyType_QuirkStillPresent()
    {
        using var session = TestKeys.OpenLoggedInSession(_backend);
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var attrKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, RandomNumberGenerator.GetBytes(32));
        Exception? ex;
        try { ex = Record.Exception(() => session.DestroyObject(session.CreateObject([attrClass, attrKeyType, attrToken, attrSensitive, attrValue]))); }
        finally { TestKeys.LogoutIfRequired(_backend, session); }

        Assert.True(ex is null,
            "C_CreateObject of a CKO_PRIVATE_KEY of type CKK_AES is now refused " +
            $"({(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name}): set " +
            "WolfPkcs11BackendFixture.WolfPkcs11RefusesAPrivateKeyOfASecretKeyType to true and delete this test.");
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
