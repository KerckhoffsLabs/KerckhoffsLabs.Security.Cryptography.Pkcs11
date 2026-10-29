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
}
