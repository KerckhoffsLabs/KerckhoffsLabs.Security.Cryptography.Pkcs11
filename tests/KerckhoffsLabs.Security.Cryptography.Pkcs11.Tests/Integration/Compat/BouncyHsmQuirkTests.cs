using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Derive;
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
    public void Sp800108DoublePipeline_QuirkStillPresent()
    {
        byte[] actual = Sp800108ChainedKdfTestCases.DeriveDoublePipeline(_backend);

        Assert.False(actual.AsSpan().SequenceEqual(Sp800108ChainedKdfTestCases.ReferenceDoublePipeline()),
            "CKM_SP800_108_DOUBLE_PIPELINE_KDF now matches SP 800-108 §5.3: set " +
            "BouncyHsmBackendFixture.BouncyHsmDoublePipelineMatchesSp800108 to true and delete this test.");
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
        session.Login(CKU.CKU_USER, pin);
        ObjectHandle handle = session.CreateObject([attrClass, attrToken, attrPrivate, attrLabel]);
        session.Logout();
        session.Login(CKU.CKU_USER, pin);
        Exception? ex;
        try { ex = Record.Exception(() => { using var read = session.GetAttributeValue(handle, [CKA.CKA_CLASS]); }); }
        finally { session.Logout(); }

        Assert.True(ex is null,
            "A private session object no longer outlives C_Logout " +
            $"(got {(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name}): set " +
            "BouncyHsmBackendFixture.BouncyHsmDestroysPrivateSessionObjectsOnLogout to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void UserLoginOverTheSo_QuirkStillPresent()
    {
        Pkcs11Slot slot = _backend.Library.GetSlotList().First(s => (NativeCULong)s.SlotId.Value == _backend.SlotId);
        using var session = slot.OpenSessionCore();
        var sid = (NativeCULong)session.SessionId;
        LowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
        Assert.Equal(CKR.CKR_OK, lowLevel.C_Login(sid, CKU.CKU_SO, _backend.SoPin.Span));
        CKR rv;
        try { rv = lowLevel.C_Login(sid, CKU.CKU_USER, _backend.UserPin.Span); }
        finally
        {
            lowLevel.C_Logout(sid);
            lowLevel.C_Logout(sid);
        }

        Assert.True(rv == CKR.CKR_OK,
            $"C_Login as the user with the SO logged in no longer answers CKR_OK (got {rv}): set " +
            "BouncyHsmBackendFixture.BouncyHsmKeepsTheSoAndTheUserApart to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void PrivateObjectAsTheSo_QuirkStillPresent()
    {
        Pkcs11Slot slot = _backend.Library.GetSlotList().First(s => (NativeCULong)s.SlotId.Value == _backend.SlotId);
        using var session = slot.OpenSessionCore();
        var sid = (NativeCULong)session.SessionId;
        LowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrPrivate = new ObjectAttribute(CKA.CKA_PRIVATE, true);
        using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, $"quirk-so-{Guid.NewGuid():N}");
        Assert.Equal(CKR.CKR_OK, lowLevel.C_Login(sid, CKU.CKU_SO, _backend.SoPin.Span));
        Exception? ex;
        try { ex = Record.Exception(() => session.DestroyObject(session.CreateObject([attrClass, attrToken, attrPrivate, attrLabel]))); }
        finally { lowLevel.C_Logout(sid); }

        Assert.True(ex is null,
            "The SO can no longer make a private object " +
            $"({(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name}): set " +
            "BouncyHsmBackendFixture.BouncyHsmRefusesPrivateObjectsToTheSo to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void MinimumPinLength_QuirkStillPresent()
    {
        TokenInfo token = _backend.Library.GetSlotList().First(s => (NativeCULong)s.SlotId.Value == _backend.SlotId).GetTokenInfo();

        Assert.True(token.MinPinLen == token.MaxPinLen && token.MinPinLen > (ulong)_backend.UserPin.Length,
            $"C_GetTokenInfo no longer reports ulMinPinLen as ulMaxPinLen (got [{token.MinPinLen}, {token.MaxPinLen}]): set " +
            "BouncyHsmBackendFixture.BouncyHsmReportsItsMinimumPinLength to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ShortMechanismList_QuirkStillPresent()
    {
        LowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
        Assert.Equal(CKR.CKR_OK, lowLevel.C_GetMechanismList(_backend.SlotId, [], out NativeCULong count));
        var shortList = new CKM[(int)(ulong)count - 1];
        CKR rv = lowLevel.C_GetMechanismList(_backend.SlotId, shortList, out NativeCULong reported);

        Assert.True(rv == CKR.CKR_BUFFER_TOO_SMALL && (ulong)reported == (ulong)shortList.Length,
            $"C_GetMechanismList into a list one short no longer leaves *pulCount as given (got {rv}, {reported} of {count}): set " +
            "BouncyHsmBackendFixture.BouncyHsmReportsTheMechanismCountOnAShortList to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SensitivePqcPrivateKey_QuirkStillPresent()
    {
        using var session = TestKeys.OpenLoggedInSession(_backend);
        CKR rv;
        ulong length;
        try
        {
            var (publicKey, privateKey) = TestKeys.GenerateMlDsaKeyPair(session, CkpMlDsa.CKP_ML_DSA_44);
            CK_ATTRIBUTE[] template = [new CK_ATTRIBUTE { type = (NativeCULong)(ulong)CKA.CKA_VALUE }];
            rv = _backend.Library.LowLevelLibrary!.C_GetAttributeValue((NativeCULong)session.SessionId, (NativeCULong)privateKey.ObjectId, template);
            length = (ulong)template[0].valueLen;
            session.DestroyObject(privateKey);
            session.DestroyObject(publicKey);
        }
        finally { session.Logout(); }

        Assert.True(rv == CKR.CKR_OK && length != CK.CK_UNAVAILABLE_INFORMATION,
            $"A sensitive ML-DSA private key no longer reveals the length of its CKA_VALUE (got {rv}): set " +
            "BouncyHsmBackendFixture.BouncyHsmHidesSensitivePqcPrivateKeys to true and delete this test.");
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
        finally { session.Logout(); }

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
        finally { session.Logout(); }

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
        finally { session.Logout(); }

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
    public void CopyUniqueId_QuirkStillPresent()
    {
        using var session = TestKeys.OpenLoggedInSession(_backend);
        byte[] original, copied;
        try
        {
            ObjectHandle data = CreateDataObject(session);
            ObjectHandle copy = session.CopyObject(data, []);
            using (var read = session.GetAttributeValue(data, [CKA.CKA_UNIQUE_ID]))
                original = read[0].GetValueAsByteArray();
            using (var read = session.GetAttributeValue(copy, [CKA.CKA_UNIQUE_ID]))
                copied = read[0].GetValueAsByteArray();
            session.DestroyObject(copy);
            session.DestroyObject(data);
        }
        finally { session.Logout(); }

        Assert.True(original.AsSpan().SequenceEqual(copied),
            "A copy no longer has the original's CKA_UNIQUE_ID: set " +
            "BouncyHsmBackendFixture.BouncyHsmGivesACopyItsOwnUniqueId to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void KeyMaterialChange_QuirkStillPresent()
    {
        using var session = TestKeys.OpenLoggedInSession(_backend);
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, false);
        using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, new byte[32]);
        byte[] replacement = [.. Enumerable.Repeat((byte)0x07, 32)];
        using var attrReplacement = new ObjectAttribute(CKA.CKA_VALUE, replacement);
        Exception? ex;
        byte[] after;
        try
        {
            ObjectHandle key = session.CreateObject([attrClass, attrKeyType, attrToken, attrSensitive, attrValue]);
            ex = Record.Exception(() => session.SetAttributeValue(key, [attrReplacement]));
            using (var read = session.GetAttributeValue(key, [CKA.CKA_VALUE]))
                after = read[0].GetValueAsByteArray();
            session.DestroyObject(key);
        }
        finally { session.Logout(); }

        Assert.True(ex is null && after.AsSpan().SequenceEqual(replacement),
            "C_SetAttributeValue no longer changes an AES key's CKA_VALUE " +
            $"({(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name ?? "value unchanged"}): set " +
            "BouncyHsmBackendFixture.BouncyHsmFixesKeyMaterial to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void PrivateFlagChange_QuirkStillPresent()
    {
        using var session = TestKeys.OpenLoggedInSession(_backend);
        using var attrPrivate = new ObjectAttribute(CKA.CKA_PRIVATE, true);
        Exception? ex;
        bool after;
        try
        {
            ObjectHandle data = CreateDataObject(session, isPrivate: false);
            ex = Record.Exception(() => session.SetAttributeValue(data, [attrPrivate]));
            using (var read = session.GetAttributeValue(data, [CKA.CKA_PRIVATE]))
                after = read[0].GetValueAsBool();
            session.DestroyObject(data);
        }
        finally { session.Logout(); }

        Assert.True(ex is null && after,
            "C_SetAttributeValue no longer makes a public object private " +
            $"({(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name ?? "flag unchanged"}): set " +
            "BouncyHsmBackendFixture.BouncyHsmFixesThePrivateAndModifiableFlags to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void MalformedAttributeValue_QuirkStillPresent()
    {
        using var session = TestKeys.OpenLoggedInSession(_backend);
        LowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
        IntPtr buffer = System.Runtime.InteropServices.Marshal.AllocHGlobal(16);
        CKR rv;
        try
        {
            System.Runtime.InteropServices.Marshal.Copy(new byte[16], 0, buffer, 16);
            // A CK_OBJECT_CLASS of zero (CKO_DATA) in the first half, a 4-byte CKA_TOKEN of zeros in the second.
            CK_ATTRIBUTE[] template =
            [
                new CK_ATTRIBUTE { type = (NativeCULong)(ulong)CKA.CKA_CLASS, value = buffer, valueLen = (NativeCULong)(ulong)System.Runtime.CompilerServices.Unsafe.SizeOf<NativeCULong>() },
                new CK_ATTRIBUTE { type = (NativeCULong)(ulong)CKA.CKA_TOKEN, value = buffer + 8, valueLen = (NativeCULong)4UL },
            ];
            rv = lowLevel.C_CreateObject((NativeCULong)session.SessionId, template, out NativeCULong created);
            if (rv == CKR.CKR_OK)
                lowLevel.C_DestroyObject((NativeCULong)session.SessionId, created);
        }
        finally
        {
            System.Runtime.InteropServices.Marshal.FreeHGlobal(buffer);
            session.Logout();
        }

        Assert.True(rv == CKR.CKR_GENERAL_ERROR,
            $"C_CreateObject with a 4-byte CKA_TOKEN no longer answers CKR_GENERAL_ERROR (got {rv}): set " +
            "BouncyHsmBackendFixture.BouncyHsmRefusesMalformedAttributeValues to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void CopyableUndone_QuirkStillPresent()
    {
        using var session = TestKeys.OpenLoggedInSession(_backend);
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrUncopyable = new ObjectAttribute(CKA.CKA_COPYABLE, false);
        using var attrCopyable = new ObjectAttribute(CKA.CKA_COPYABLE, true);
        Exception? ex;
        bool after;
        try
        {
            ObjectHandle data = session.CreateObject([attrClass, attrToken, attrUncopyable]);
            ex = Record.Exception(() => session.SetAttributeValue(data, [attrCopyable]));
            using (var read = session.GetAttributeValue(data, [CKA.CKA_COPYABLE]))
                after = read[0].GetValueAsBool();
            session.DestroyObject(data);
        }
        finally { session.Logout(); }

        Assert.True(ex is null && after,
            "C_SetAttributeValue no longer sets CKA_COPYABLE back to TRUE " +
            $"({(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name ?? "flag unchanged"}): set " +
            "BouncyHsmBackendFixture.BouncyHsmKeepsCkaCopyableFalse to true and delete this test.");
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
    public void NonKeyObjectAsAKey_QuirkStillPresent()
    {
        using var session = TestKeys.OpenLoggedInSession(_backend);
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, new byte[32]);
        ObjectHandle data = session.CreateObject([attrClass, attrToken, attrValue]);
        CKR rv;
        try
        {
            using var scope = new MechanismParameterScope();
            CK_MECHANISM mech = new Mechanism(CKM.CKM_SHA256_HMAC).Marshal(scope, out _);
            rv = _backend.Library.LowLevelLibrary!.C_SignInit((NativeCULong)session.SessionId, in mech, (NativeCULong)data.ObjectId);
        }
        finally
        {
            session.DestroyObject(data);
            TestKeys.LogoutIfRequired(_backend, session);
        }

        Assert.True(rv == CKR.CKR_OBJECT_HANDLE_INVALID,
            $"C_SignInit(CKM_SHA256_HMAC) with a data object no longer answers CKR_OBJECT_HANDLE_INVALID (got {rv}): set " +
            "BouncyHsmBackendFixture.BouncyHsmRefusesANonKeyObjectAsAKey to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void AesCtrParams_QuirkStillPresent()
    {
        using var session = TestKeys.OpenLoggedInSession(_backend);
        ObjectHandle key = TestKeys.CreateAes256Key(session, System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        CKR rv;
        try
        {
            // CK_AES_CTR_PARAMS: ulCounterBits = 128, then a 16-byte counter block.
            byte[] parameter = new byte[System.Runtime.CompilerServices.Unsafe.SizeOf<NativeCULong>() + 16];
            parameter[0] = 128;
            System.Security.Cryptography.RandomNumberGenerator.Fill(parameter.AsSpan(parameter.Length - 16));
            using var scope = new MechanismParameterScope();
#pragma warning disable KLPKCS11009 // CKM_AES_CTR through the raw dispatch.
            CK_MECHANISM mech = new Mechanism(CKM.CKM_AES_CTR, parameter).Marshal(scope, out _);
#pragma warning restore KLPKCS11009
            rv = _backend.Library.LowLevelLibrary!.C_EncryptInit((NativeCULong)session.SessionId, in mech, (NativeCULong)key.ObjectId);
            if (rv == CKR.CKR_OK)
                _backend.Library.LowLevelLibrary!.C_SessionCancel((NativeCULong)session.SessionId, (NativeCULong)CKF.CKF_ENCRYPT);
        }
        finally
        {
            session.DestroyObject(key);
            TestKeys.LogoutIfRequired(_backend, session);
        }

        Assert.True(rv == CKR.CKR_GENERAL_ERROR,
            $"C_EncryptInit(CKM_AES_CTR) with a CK_AES_CTR_PARAMS no longer answers CKR_GENERAL_ERROR (got {rv}): set " +
            "BouncyHsmBackendFixture.BouncyHsmTakesAesCtrParams to true and delete this test.");
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
            ex = Record.Exception(() => session.DestroyObject(session.UnwrapKey(oaep, priv, wrapped[..^1], [c, t, tok, enc])));
        }
        finally
        {
            session.DestroyObject(priv);
            session.DestroyObject(pub);
            TestKeys.LogoutIfRequired(_backend, session);
        }

        Assert.True(ex is Pkcs11Exception { ReturnValue: CKR.CKR_GENERAL_ERROR },
            $"C_UnwrapKey(CKM_RSA_PKCS_OAEP) of a 255-byte blob under a 2048-bit key no longer answers CKR_GENERAL_ERROR (got {ex?.Message ?? "no error"}): set " +
            "BouncyHsmBackendFixture.BouncyHsmRefusesAnOaepBlobByItsLength to true and delete this test.");
    }
}
