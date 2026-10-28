using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Compat;

/// <summary>
/// One test per NSS softoken bug a gate on <see cref="NssBackendFixture"/> works around: each reproduces
/// the bug directly and asserts that it is still there. When an NSS bump brings the upstream fix, the
/// matching test fails, telling us to remove the gate so the shared test cases run again.
/// </summary>
[Collection("Nss")]
public sealed class NssQuirkTests(NssBackendFixture backend)
{
    private readonly IPkcs11Backend _backend = backend;

    // https://bugzilla.mozilla.org/show_bug.cgi?id=2075845
    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void CmacVerify_QuirkStillPresent()
    {
        _backend.RequireMechanism(CKM.CKM_AES_CMAC);
        using var session = _backend.OpenSession();
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label($"quirk-cmac-{Guid.NewGuid():N}").Value(new byte[16]).Sign().Verify().Build();
        using var key = session.ImportKey(template);
        var cmac = new Mechanism(CKM.CKM_AES_CMAC);
        byte[] mac = key.Sign(cmac, [1, 2, 3]);

        var ex = Record.Exception(() => key.Verify(cmac, [1, 2, 3], mac));

        Assert.True(ex is Pkcs11Exception { ReturnValue: CKR.CKR_MECHANISM_INVALID },
            "C_VerifyInit with CKM_AES_CMAC no longer gives CKR_MECHANISM_INVALID " +
            $"(got {(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name ?? "no exception"}): set " +
            "NssBackendFixture.SupportsCmacVerify to true and delete this test.");
    }

    // https://bugzilla.mozilla.org/show_bug.cgi?id=2075840
    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void GeneratedKeyLocal_QuirkStillPresent()
    {
        _backend.RequireMechanism(CKM.CKM_AES_KEY_GEN);
        using var session = _backend.OpenSession();
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label($"quirk-local-{Guid.NewGuid():N}").ValueLen(32).Encrypt().Build();
        using var key = session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), template);
        using var attributes = key.GetAttributeValue(CKA.CKA_LOCAL);

        Assert.False(attributes[0].GetValueAsBool(),
            "A key NSS generates now reports CKA_LOCAL true: set NssBackendFixture.SupportsLocalOnGeneratedKeys " +
            "to true and delete this test.");
    }
}
