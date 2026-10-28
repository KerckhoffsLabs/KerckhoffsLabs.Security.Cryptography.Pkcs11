using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Compat;

/// <summary>
/// One test per Craton HSM gap a gate on <see cref="CratonHsmBackendFixture"/> works around: each reproduces
/// it directly and asserts that it is still there. When a Craton bump brings the fix, the matching test
/// fails, telling us to remove the gate so the shared test cases run again.
/// </summary>
[Collection("CratonHsm")]
public sealed class CratonHsmQuirkTests(CratonHsmBackendFixture backend)
{
    private readonly IPkcs11Backend _backend = backend;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void LocalAttribute_QuirkStillPresent()
    {
        _backend.RequireMechanism(CKM.CKM_AES_KEY_GEN);
        using var session = _backend.OpenSession();
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label($"quirk-local-{Guid.NewGuid():N}").ValueLen(32).Encrypt().OnToken(_backend.SupportsTokenObjects).Build();
        using var key = session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), template);
        try
        {
            using var attributes = key.GetAttributeValue(CKA.CKA_LOCAL);

            Assert.True(attributes[0].CannotBeRead,
                "Craton HSM now returns CKA_LOCAL: set CratonHsmBackendFixture.SupportsLocalAttribute to true and " +
                "delete this test.");
        }
        finally
        {
            try { key.Destroy(); } catch (Pkcs11Exception) { /* best-effort cleanup */ }
        }
    }
}
