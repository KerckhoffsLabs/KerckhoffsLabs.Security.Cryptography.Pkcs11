using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Compat;

/// <summary>
/// Runs only on the dedicated CI leg that loads a real SoftHSM 2.5 (signalled by
/// <c>PKCS11_TEST_EXPECT_SOFTHSM_V240=1</c>). SoftHSM 2.5 predates the v3.0 <c>C_GetInterface</c>
/// API, so it is a genuine PKCS#11 v2.40-only module — the authentic counterpart of the synthetic
/// gate-240 shim. These tests fail the leg loudly if the loaded module is not actually v2.40, which
/// is how "ensure this SoftHSM uses Cryptoki v2.40" is enforced rather than assumed.
/// </summary>
[Collection("SoftHsm")]
public sealed class SoftHsmV240ComplianceTests(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;

    public static bool ExpectV240 =>
        string.Equals(Environment.GetEnvironmentVariable("PKCS11_TEST_EXPECT_SOFTHSM_V240"), "1", StringComparison.Ordinal)
        && SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(ExpectV240))]
    public void Module_ReportsCryptokiVersion_2_40()
        => Assert.Equal("2.40", _backend.Library.GetInfo().CryptokiVersion);

    [ConditionalFact(nameof(ExpectV240))]
    public void Module_ExposesNoV3xSurface()
    {
        using var pin = new SecurePin(_backend.UserPin.Span);
        using var workspace = _backend.Library.OpenWorkspace(_backend.TokenLabel, CKU.CKU_USER, pin);

        // A v2.40 module negotiates neither the v3.0 message API nor the v3.2 additions.
        Assert.False(workspace.Session.SupportsMessageApi);
        Assert.False(workspace.Session.SupportsV32Api);
    }

    [ConditionalFact(nameof(ExpectV240))]
    public void GetInterfaces_Throws_FunctionNotSupported()
    {
        // C_GetInterface does not exist before v3.0; the wrapper surfaces that as a typed CKR.
        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => _backend.Library.GetInterfaces());
        Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
    }
}
