using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Derive;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Objects;
using Xunit.Sdk;

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
    public void Sp800108AdditionalKey_QuirkStillPresent()
    {
        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => Sp800108ChainedKdfTestCases.Assert_Counter_AdditionalDerivedKey_TakesTheNextBytes(_backend));
        Assert.True(ex.ReturnValue == CKR.CKR_GENERAL_ERROR,
            $"An SP 800-108 derive with an additional key now answers {ex.ReturnValue}, not CKR_GENERAL_ERROR: if it derives, set " +
            "BouncyHsmBackendFixture.BouncyHsmDerivesAdditionalSp800108Keys to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void PrivateSessionObjectAfterLogout_QuirkStillPresent()
    {
        Pkcs11Slot slot = _backend.Library.GetSlotList().First(s => (NativeCULong)s.SlotId.Value == _backend.SlotId);
        using var session = slot.OpenSessionCore();
        using var pin = new SecurePin(_backend.UserPin.Span);
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrPrivate = new ObjectAttribute(CKA.CKA_PRIVATE, true);
        using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, $"quirk-logout-{Guid.NewGuid():N}");
        session.SendLogin(CKU.CKU_USER, pin.Pin);
        ObjectHandle handle = session.CreateObject([attrClass, attrToken, attrPrivate, attrLabel]);
        session.SendLogout();
        session.SendLogin(CKU.CKU_USER, pin.Pin);
        Exception? ex;
        try { ex = Record.Exception(() => { using var read = session.GetAttributeValue(handle, [CKA.CKA_CLASS]); }); }
        finally { session.SendLogout(); }

        Assert.True(ex is null,
            "A private session object no longer outlives C_Logout " +
            $"(got {(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name}): set " +
            "BouncyHsmBackendFixture.BouncyHsmDestroysPrivateSessionObjectsOnLogout to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void MissingKeyAttribute_QuirkStillPresent()
    {
        using var session = TestKeys.OpenLoggedInSession(_backend);
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var attrKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrExponent = new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, (byte[])[0x01, 0x00, 0x01]);
        Exception? ex;
        try { ex = Record.Exception(() => session.DestroyObject(session.CreateObject([attrClass, attrKeyType, attrToken, attrExponent]))); }
        finally { session.SendLogout(); }

        Assert.True(ex is Pkcs11Exception { ReturnValue: CKR.CKR_ATTRIBUTE_VALUE_INVALID },
            "C_CreateObject of an RSA public key without CKA_MODULUS no longer answers CKR_ATTRIBUTE_VALUE_INVALID " +
            $"(got {(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name ?? "success"}): set " +
            "BouncyHsmBackendFixture.BouncyHsmReportsAMissingKeyAttributeAsIncomplete to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SecretKeyWithoutAKeyType_QuirkStillPresent()
    {
        using var session = TestKeys.OpenLoggedInSession(_backend);
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, new byte[32]);
        Exception? ex;
        try { ex = Record.Exception(() => session.DestroyObject(session.CreateObject([attrClass, attrToken, attrValue]))); }
        finally { session.SendLogout(); }

        Assert.True(ex is null,
            "C_CreateObject of a secret key without CKA_KEY_TYPE no longer makes a key " +
            $"({(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name}): set " +
            "BouncyHsmBackendFixture.BouncyHsmRefusesASecretKeyWithoutAKeyType to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void KeyPairTemplateKeyType_QuirkStillPresent()
    {
        using var session = TestKeys.OpenLoggedInSession(_backend);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrEcParams = new ObjectAttribute(CKA.CKA_EC_PARAMS, TestKeys.EcP256Oid);
        using var attrRsa = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA);
        using var attrSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        Exception? ex;
        try
        {
            ex = Record.Exception(() =>
            {
                session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), [attrToken, attrEcParams], [attrToken, attrRsa, attrSensitive],
                    out ObjectHandle publicKey, out ObjectHandle privateKey);
                session.DestroyObject(privateKey);
                session.DestroyObject(publicKey);
            });
        }
        finally { session.SendLogout(); }

        Assert.True(ex is null,
            "C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN) with CKK_RSA in the private template is now refused " +
            $"({(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name}): set " +
            "BouncyHsmBackendFixture.BouncyHsmChecksTheKeyPairTemplatesClassAndKeyType to true and delete this test.");
    }

    private static ObjectHandle CreateDataObject(Pkcs11SessionCore session, bool isPrivate = false)
    {
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrPrivate = new ObjectAttribute(CKA.CKA_PRIVATE, isPrivate);
        using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, (byte[])[0x01]);
        return session.CreateObject([attrClass, attrToken, attrPrivate, attrValue]);
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void KeyMaterialChange_QuirkStillPresent()
    {
        foreach (string component in (string[])["EC CKA_EC_POINT", "RSA CKA_PUBLIC_EXPONENT"])
        {
            Exception? failure = Record.Exception(() => ObjectConformanceTestCases.Assert_KeyComponent_IsReadOnly(_backend, component));
            Assert.True(failure is XunitException and not SkipException,
                $"C_SetAttributeValue no longer changes a public key's {component} ({failure?.Message ?? "the case passes"}): set " +
                "BouncyHsmBackendFixture.BouncyHsmFixesKeyMaterial to true and delete this test.");
        }
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ModifiableFlagChange_QuirkStillPresent()
    {
        Exception? failure = Record.Exception(() => ObjectConformanceTestCases.Assert_SetAttributeValue_ReadOnlyKeyAttribute_IsRefused(_backend, CKA.CKA_MODIFIABLE));
        Assert.True(failure is XunitException and not SkipException,
            $"C_SetAttributeValue no longer changes CKA_MODIFIABLE ({failure?.Message ?? "the case passes"}): set " +
            "BouncyHsmBackendFixture.BouncyHsmFixesTheModifiableFlag to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void UniqueIdInACopyTemplate_QuirkStillPresent()
    {
        using var session = TestKeys.OpenLoggedInSession(_backend);
        using var attrUniqueId = new ObjectAttribute(CKA.CKA_UNIQUE_ID, "kl-chosen-id");
        Exception? ex;
        try
        {
            ObjectHandle data = CreateDataObject(session);
            ex = Record.Exception(() => session.DestroyObject(session.CopyObject(data, [attrUniqueId])));
            session.DestroyObject(data);
        }
        finally { session.SendLogout(); }

        Assert.True(ex is null,
            "C_CopyObject with a CKA_UNIQUE_ID in its template is now refused " +
            $"({(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name}): set " +
            "BouncyHsmBackendFixture.BouncyHsmRefusesAUniqueIdInACopyTemplate to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void DerivedNeverExtractable_QuirkStillPresent()
    {
        Exception? failure = Record.Exception(() => KeyProvenanceTestCases.Assert_DerivedKey_TakesItsHistoryFromTheBase(_backend, "HKDF"));
        Assert.True(failure is XunitException and not SkipException && failure.Message.Contains("CKA_NEVER_EXTRACTABLE is False", StringComparison.Ordinal),
            $"An unextractable HKDF key from a never-extractable base no longer reports CKA_NEVER_EXTRACTABLE FALSE ({failure?.Message ?? "the case passes"}): set " +
            "BouncyHsmBackendFixture.BouncyHsmSetsADerivedKeysNeverExtractable to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EmptyDigestStream_QuirkStillPresent()
    {
        Exception? ex = Record.Exception(() => BufferConventionTestCases.Assert_Digest_EmptyStream_IsTheHashOfNothing(_backend));

        Assert.True(ex is Pkcs11Exception { ReturnValue: CKR.CKR_DATA_LEN_RANGE },
            "C_DigestFinal of an empty stream no longer gives CKR_DATA_LEN_RANGE " +
            $"(got {(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name ?? "no exception"}): set " +
            "BouncyHsmBackendFixture.BouncyHsmFinishesAnEmptyDigestStream to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void NewPinOutsideTheLengthRange_QuirkStillPresent()
    {
        TokenInfo token = _backend.Library.GetSlotList().First(s => (NativeCULong)s.SlotId.Value == _backend.SlotId).GetTokenInfo();
        byte[] shortPin = [.. Enumerable.Repeat((byte)'7', (int)token.MinPinLen - 1)];
        Pkcs11Slot slot = _backend.Library.GetSlotList().First(s => (NativeCULong)s.SlotId.Value == _backend.SlotId);
        using var session = slot.OpenSessionCore();
        var sid = (NativeCULong)session.SessionId;
        LowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
        Assert.Equal(CKR.CKR_OK, lowLevel.C_Login(sid, CKU.CKU_USER, _backend.UserPin.Span));
        CKR rv;
        try
        {
            rv = lowLevel.C_SetPIN(sid, _backend.UserPin.Span, shortPin);
            if (rv == CKR.CKR_OK)
                Assert.Equal(CKR.CKR_OK, lowLevel.C_SetPIN(sid, shortPin, _backend.UserPin.Span));
        }
        finally { lowLevel.C_Logout(sid); }

        Assert.True(rv == CKR.CKR_OK,
            $"C_SetPIN to a {shortPin.Length}-byte PIN (ulMinPinLen {token.MinPinLen}) no longer answers CKR_OK (got {rv}): set " +
            "BouncyHsmBackendFixture.BouncyHsmRefusesANewPinOutsideTheLengthRange to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void KeyOfTheWrongClass_QuirkStillPresent()
    {
        using var session = TestKeys.OpenLoggedInSession(_backend);
        LowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var (pub, priv) = TestKeys.ImportRsaRecoveryKeyPair(session, rsa);
        CKR rv;
        try
        {
            using var scope = new MechanismParameterScope();
#pragma warning disable KLPKCS11008 // CKM_RSA_PKCS for a signature with recovery, through the raw dispatch.
            CK_MECHANISM mech = new Mechanism(CKM.CKM_RSA_PKCS).Marshal(scope, out _);
#pragma warning restore KLPKCS11008
            rv = lowLevel.C_SignRecoverInit((NativeCULong)session.SessionId, in mech, (NativeCULong)pub.ObjectId);
        }
        finally
        {
            session.DestroyObject(priv);
            session.DestroyObject(pub);
            TestKeys.LogoutIfRequired(_backend, session);
        }

        Assert.True(rv == CKR.CKR_KEY_HANDLE_INVALID,
            $"C_SignRecoverInit with an RSA public key no longer answers CKR_KEY_HANDLE_INVALID (got {rv}): set " +
            "BouncyHsmBackendFixture.BouncyHsmReportsAKeyOfTheWrongClassAsInconsistent to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EmptyCbcPadCiphertext_QuirkStillPresent()
    {
        using var session = TestKeys.OpenLoggedInSession(_backend);
        LowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
        var sid = (NativeCULong)session.SessionId;
        ObjectHandle key = TestKeys.CreateAes256Key(session, System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        CKR rv;
        NativeCULong length;
        try
        {
            using (var scope = new MechanismParameterScope())
            {
#pragma warning disable KLPKCS11009 // CKM_AES_CBC_PAD through the raw dispatch.
                CK_MECHANISM mech = new Mechanism(CKM.CKM_AES_CBC_PAD, new byte[16]).Marshal(scope, out _);
#pragma warning restore KLPKCS11009
                Assert.Equal(CKR.CKR_OK, lowLevel.C_DecryptInit(sid, in mech, (NativeCULong)key.ObjectId));
            }
            rv = lowLevel.C_Decrypt(sid, [], new byte[32], lengthOnly: false, out length);
            lowLevel.C_SessionCancel(sid, (NativeCULong)CKF.CKF_DECRYPT);
        }
        finally
        {
            session.DestroyObject(key);
            TestKeys.LogoutIfRequired(_backend, session);
        }

        Assert.True(rv == CKR.CKR_OK && (ulong)length == 0,
            $"C_Decrypt(CKM_AES_CBC_PAD) of an empty ciphertext now gives {rv} with {length} bytes: set " +
            "BouncyHsmBackendFixture.BouncyHsmRefusesAnEmptyCbcPadCiphertext to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void OaepBlobOfTheWrongLength_QuirkStillPresent()
    {
        using var session = TestKeys.OpenLoggedInSession(_backend);
        var (pub, priv) = TestKeys.GenerateRsa2048KeyPair(session);
        Exception? ex;
        try
        {
            var oaep = new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256));
            byte[] wrapped = session.Encrypt(oaep, pub, new byte[32]);
            using var c = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var t = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
            using var tok = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var enc = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
            ex = Record.Exception(() => session.DestroyObject(session.UnwrapKey(oaep, priv, [.. wrapped, 0x00], [c, t, tok, enc])));
        }
        finally
        {
            session.DestroyObject(priv);
            session.DestroyObject(pub);
            TestKeys.LogoutIfRequired(_backend, session);
        }

        Assert.True(ex is Pkcs11Exception { ReturnValue: CKR.CKR_WRAPPED_KEY_INVALID },
            $"C_UnwrapKey(CKM_RSA_PKCS_OAEP) of a 257-byte blob under a 2048-bit key no longer answers CKR_WRAPPED_KEY_INVALID (got {ex?.Message ?? "no error"}): set " +
            "BouncyHsmBackendFixture.BouncyHsmRefusesAnOaepBlobByItsLength to true and delete this test.");
    }

    // A raw CK_GCM_PARAMS with a 12-byte IV, so that the module sees the fields as given.
    private static Mechanism RawGcm(NativeBuffers buffers, byte[] iv, IntPtr aad, ulong aadLen, ulong tagBits)
    {
        var parameter = new CK_GCM_PARAMS
        {
            Iv = buffers.Of(iv),
            IvLen = (NativeCULong)12UL,
            IvBits = (NativeCULong)96UL,
            AAD = aad,
            AADLen = (NativeCULong)aadLen,
            TagBits = (NativeCULong)tagBits,
        };
        return RawParameter.From(CKM.CKM_AES_GCM, in parameter);
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void OutOfRangeAeadParameter_QuirkStillPresent()
    {
        using var session = TestKeys.OpenLoggedInSession(_backend);
        LowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
        var sid = (NativeCULong)session.SessionId;
        ObjectHandle key = TestKeys.CreateAes256Key(session, System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        CKR rv;
        try
        {
            using var buffers = new NativeBuffers();
            using var scope = new MechanismParameterScope();
            CK_MECHANISM mech = RawGcm(buffers, new byte[12], buffers.Of([1, 2, 3]), 3, 136).Marshal(scope, out _);
            rv = lowLevel.C_EncryptInit(sid, in mech, (NativeCULong)key.ObjectId);
            if (rv == CKR.CKR_OK)
                lowLevel.C_SessionCancel(sid, (NativeCULong)CKF.CKF_ENCRYPT);
        }
        finally
        {
            session.DestroyObject(key);
            TestKeys.LogoutIfRequired(_backend, session);
        }

        Assert.True(rv == CKR.CKR_GENERAL_ERROR,
            $"C_EncryptInit(CKM_AES_GCM) with ulTagBits 136 no longer answers CKR_GENERAL_ERROR (got {rv}): set " +
            "BouncyHsmBackendFixture.BouncyHsmRefusesAnOutOfRangeAeadParameterAsInvalid to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void NullAadPointer_QuirkStillPresent()
    {
        using var session = TestKeys.OpenLoggedInSession(_backend);
        LowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
        var sid = (NativeCULong)session.SessionId;
        byte[] rawKey = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        byte[] iv = System.Security.Cryptography.RandomNumberGenerator.GetBytes(12);
        byte[] plaintext = new byte[20];
        ObjectHandle key = TestKeys.CreateAes256Key(session, rawKey);
        CKR rv;
        byte[] output = new byte[36];
        try
        {
            using var buffers = new NativeBuffers();
            using var scope = new MechanismParameterScope();
            CK_MECHANISM mech = RawGcm(buffers, iv, IntPtr.Zero, 9, 128).Marshal(scope, out _);
            rv = lowLevel.C_EncryptInit(sid, in mech, (NativeCULong)key.ObjectId);
            if (rv == CKR.CKR_OK)
                Assert.Equal(CKR.CKR_OK, lowLevel.C_Encrypt(sid, plaintext, output, lengthOnly: false, out _));
        }
        finally
        {
            session.DestroyObject(key);
            TestKeys.LogoutIfRequired(_backend, session);
        }

        byte[] expected = new byte[36];
        using (var bcl = new System.Security.Cryptography.AesGcm(rawKey, 16))
            bcl.Encrypt(iv, plaintext, expected.AsSpan(0, 20), expected.AsSpan(20), []);
        Assert.True(rv == CKR.CKR_OK && output.AsSpan().SequenceEqual(expected),
            $"C_EncryptInit(CKM_AES_GCM) with a NULL pAAD and ulAADLen 9 no longer runs with no AAD (got {rv}): set " +
            "BouncyHsmBackendFixture.BouncyHsmRefusesANullAadPointer to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ParameterLengthAbove32Bits_QuirkStillPresent()
    {
        Assert.SkipUnless(UnmanagedMemory.NativeULongSize == 8, "CK_ULONG is 32 bits on this platform.");
        using var session = TestKeys.OpenLoggedInSession(_backend);
        LowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
        var sid = (NativeCULong)session.SessionId;
        byte[] rawKey = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        byte[] data = "the quick brown fox"u8.ToArray();
        using var keyClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var keyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
        using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var sign = new ObjectAttribute(CKA.CKA_SIGN, true);
        using var value = new ObjectAttribute(CKA.CKA_VALUE, rawKey);
        ObjectHandle key = session.CreateObject([keyClass, keyType, token, sign, value]);
        CKR rv;
        byte[] mac = new byte[64];
        NativeCULong length = default;
        try
        {
            byte[] parameter = new byte[8];
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(parameter, (1UL << 32) + 16);
            using var scope = new MechanismParameterScope();
            CK_MECHANISM mech = new Mechanism(CKM.CKM_SHA256_HMAC_GENERAL, parameter).Marshal(scope, out _);
            rv = lowLevel.C_SignInit(sid, in mech, (NativeCULong)key.ObjectId);
            if (rv == CKR.CKR_OK)
                Assert.Equal(CKR.CKR_OK, lowLevel.C_Sign(sid, data, mac, lengthOnly: false, out length));
        }
        finally
        {
            session.DestroyObject(key);
            TestKeys.LogoutIfRequired(_backend, session);
        }

        byte[] truncated = System.Security.Cryptography.HMACSHA256.HashData(rawKey, data)[..16];
        Assert.True(rv == CKR.CKR_OK && mac.AsSpan(0, (int)(ulong)length).SequenceEqual(truncated),
            $"C_SignInit(CKM_SHA256_HMAC_GENERAL) with a MAC length of 2^32 + 16 no longer gives a 16-byte MAC (got {rv}, {length} bytes): set " +
            "BouncyHsmBackendFixture.BouncyHsmRefusesAParameterLengthAbove32Bits to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void NullOaepLabel_QuirkStillPresent()
    {
        using var session = TestKeys.OpenLoggedInSession(_backend);
        LowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
        var sid = (NativeCULong)session.SessionId;
        var (pub, priv) = TestKeys.GenerateRsa2048KeyPair(session);
        byte[] plaintext = "the quick brown fox"u8.ToArray();
        CKR rv;
        byte[] ciphertext = new byte[256];
        byte[]? decrypted = null;
        try
        {
            var parameter = new CK_RSA_PKCS_OAEP_PARAMS
            {
                HashAlg = (NativeCULong)(ulong)CKM.CKM_SHA256,
                Mgf = (NativeCULong)(ulong)CKG.CKG_MGF1_SHA256,
                Source = (NativeCULong)CKZ.CKZ_DATA_SPECIFIED,
                SourceData = IntPtr.Zero,
                SourceDataLen = (NativeCULong)8UL,
            };
            using (var scope = new MechanismParameterScope())
            {
                CK_MECHANISM mech = RawParameter.From(CKM.CKM_RSA_PKCS_OAEP, in parameter).Marshal(scope, out _);
                rv = lowLevel.C_EncryptInit(sid, in mech, (NativeCULong)pub.ObjectId);
            }
            if (rv == CKR.CKR_OK)
            {
                Assert.Equal(CKR.CKR_OK, lowLevel.C_Encrypt(sid, plaintext, ciphertext, lengthOnly: false, out _));
                decrypted = session.Decrypt(new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256)), priv, ciphertext);
            }
        }
        finally
        {
            session.DestroyObject(priv);
            session.DestroyObject(pub);
            TestKeys.LogoutIfRequired(_backend, session);
        }

        Assert.True(rv == CKR.CKR_OK && decrypted is not null && decrypted.AsSpan().SequenceEqual(plaintext),
            $"C_EncryptInit(CKM_RSA_PKCS_OAEP) with a NULL pSourceData and ulSourceDataLen 8 no longer encrypts with the empty label (got {rv}): set " +
            "BouncyHsmBackendFixture.BouncyHsmRefusesANullOaepLabel to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EcdhSharedDataWithCkdNull_QuirkStillPresent()
    {
        var (rv, value) = Mechanisms.AlgorithmConformanceTestCases.DeriveEcdhWithFault(_backend, "CKD_NULL with shared data");

        Assert.True(rv == CKR.CKR_OK && value is not null && value.AsSpan().SequenceEqual(Mechanisms.AlgorithmConformanceTestCases.EcdhSecret),
            $"C_DeriveKey(CKM_ECDH1_DERIVE) with CKD_NULL and shared data no longer derives Z (got {rv}): set " +
            "BouncyHsmBackendFixture.BouncyHsmRefusesSharedDataWithCkdNull to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EcdhValueLenAboveTheSecret_QuirkStillPresent()
    {
        var (rv, value) = Mechanisms.AlgorithmConformanceTestCases.DeriveEcdhWithFault(_backend, "CKA_VALUE_LEN 33");

        Assert.True(rv == CKR.CKR_OK && value is not null && value.AsSpan().SequenceEqual((byte[])[0x00, .. Mechanisms.AlgorithmConformanceTestCases.EcdhSecret.ToArray()]),
            $"C_DeriveKey(CKM_ECDH1_DERIVE) on P-256 with CKA_VALUE_LEN 33 no longer makes 00 || Z (got {rv}): set " +
            "BouncyHsmBackendFixture.BouncyHsmRefusesAnEcdhValueLenAboveTheSecret to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void DerivedAesKeyOfAnInvalidLength_QuirkStillPresent()
    {
        CKR rv = Mechanisms.AlgorithmConformanceTestCases.DeriveEcdhAesKey(_backend, 13);

        Assert.True(rv == CKR.CKR_GENERAL_ERROR,
            $"C_DeriveKey(CKM_ECDH1_DERIVE) of a 13-byte AES key no longer answers CKR_GENERAL_ERROR (got {rv}): set " +
            "BouncyHsmBackendFixture.BouncyHsmRefusesAnAesKeyOfAnInvalidLengthAsInvalid to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void AesCtrCounterBitsRange_QuirkStillPresent()
    {
        foreach (ulong counterBits in (ulong[])[0, 129])
        {
            Exception? ex = Record.Exception(() => Integration.Mechanisms.MechanismParameterTestCases.Assert_AesCtr_CounterBitsOutOfRange_IsMechanismParamInvalid(_backend, counterBits));
            Assert.True(ex is not null && ex.Message.Contains("returned CKR_OK", StringComparison.Ordinal),
                $"C_EncryptInit(CKM_AES_CTR) with ulCounterBits {counterBits} is no longer accepted ({ex?.Message ?? "the case passes"}): " +
                "if it answers CKR_MECHANISM_PARAM_INVALID, set BouncyHsmBackendFixture.BouncyHsmRefusesOutOfRangeAesCtrCounterBits to true and delete this test.");
        }
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void AesCtrCounterOverflow_QuirkStillPresent()
    {
        Exception? ex = Record.Exception(() => Integration.Mechanisms.MechanismParameterTestCases.Assert_AesCtr_CounterOverflow_IsDataLenRange(_backend));
        Assert.True(ex is not null && ex.Message.Contains("returned CKR_OK", StringComparison.Ordinal),
            $"A CKM_AES_CTR message past the end of its counter is no longer encrypted ({ex?.Message ?? "the case passes"}): " +
            "if it answers CKR_DATA_LEN_RANGE, set BouncyHsmBackendFixture.BouncyHsmRefusesAesCtrCounterOverflow to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void BaseKeyProtection_QuirkStillPresent()
    {
        Exception? failure = Record.Exception(() => BaseKeyProtectionTestCases.Assert_KeyMadeFromAProtectedKey_KeepsItsProtection(_backend, "CONCATENATE_BASE_AND_DATA; sensitive and unextractable"));
        Assert.True(failure is XunitException and not SkipException,
            "BouncyHsm now gives a key derived from a protected key and data the base key's protection (harrison314/BouncyHsm#141): set " +
            "BouncyHsmBackendFixture.BouncyHsmKeepsABaseKeysProtection to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void AllowedMechanismsCopy_QuirkStillPresent()
    {
        Exception? failure = Record.Exception(() => ObjectConformanceTestCases.Assert_CopyObject_CannotMakeThatChange(_backend, "CKA_ALLOWED_MECHANISMS, wider"));
        Assert.True(failure is XunitException and not SkipException,
            "BouncyHsm no longer lets a copy change CKA_ALLOWED_MECHANISMS: set " +
            "BouncyHsmBackendFixture.BouncyHsmKeepsAllowedMechanismsOnACopy to true and delete this test.");
    }

    // The harrison314/BouncyHsm#145 canary. On the shared token, which is not a qualified-area one (so it needs no
    // QualifiedAreaToken): the case puts CKA_ALWAYS_AUTHENTICATE in the template. A skip from inside the case (the
    // token lacks the mechanisms or a login) is a skip here too, not the quirk's disappearance.
    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void AlwaysAuthenticateInATemplate_QuirkStillPresent()
    {
        Exception? ex = Record.Exception(() => TokenLoginTestCases.Assert_AlwaysAuthenticateKey_SignsWithContextLogin(_backend));
        if (ex is SkipException skip)
            Assert.Skip(skip.Message);

        Assert.True(ex is Pkcs11Exception { ReturnValue: CKR.CKR_ATTRIBUTE_READ_ONLY },
            "C_GenerateKeyPair with CKA_ALWAYS_AUTHENTICATE in the private template no longer gives CKR_ATTRIBUTE_READ_ONLY " +
            $"(got {(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name ?? "no exception"}): delete " +
            "this test and BouncyHsmBackendFixture.BouncyHsmTakesAlwaysAuthenticateInATemplate (harrison314/BouncyHsm#145).");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SecondKeysAllowedMechanisms_QuirkStillPresent()
    {
        Exception? failure = Record.Exception(() => BaseKeyProtectionTestCases.Assert_SecondKeysAllowedMechanisms_AreEnforced(_backend, "excludes it"));
        Assert.True(failure is XunitException and not SkipException,
            "BouncyHsm now refuses CKM_CONCATENATE_BASE_AND_KEY with a second key whose CKA_ALLOWED_MECHANISMS leaves it out: make " +
            "BouncyHsmBackendFixture.BouncyHsmChecksTheSecondKeysAllowedMechanisms true and delete this test.");
    }

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(BaseKeyProtectionTestCases.OneByteDerivations), MemberType = typeof(BaseKeyProtectionTestCases))]
    public void OneByteKeyDigest_QuirkStillPresent(string derivation)
    {
        Exception? failure = Record.Exception(() => BaseKeyProtectionTestCases.Assert_OneByteKeyFromAProtectedKey_GivesNoByteAway(_backend, derivation));
        Assert.True(failure is XunitException and not SkipException,
            $"BouncyHsm no longer gives a byte of a protected key away through a one-byte key ({derivation}): make " +
            "BouncyHsmBackendFixture.BouncyHsmKeepsAProtectedKeysBytesFromADigest true and delete this test.");
    }

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [InlineData("ECDSA sign with an AES key")]
    [InlineData("ECDH derive from an AES key")]
    public void KeyOfTheWrongType_QuirkStillPresent(string misuse)
    {
        Exception? failure = Record.Exception(() => OperationStateTestCases.Assert_KeyOfTheWrongType_IsRefused(_backend, misuse));
        Assert.True(failure is XunitException and not SkipException,
            $"BouncyHsm now answers {misuse} with CKR_KEY_TYPE_INCONSISTENT: make " +
            "BouncyHsmBackendFixture.BouncyHsmReportsAKeyOfTheWrongTypeAsInconsistent true and delete this test.");
    }
}
