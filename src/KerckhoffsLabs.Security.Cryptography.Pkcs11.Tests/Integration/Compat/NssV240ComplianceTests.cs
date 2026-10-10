using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Compat;

/// <summary>
/// Runs only on the dedicated CI leg that loads a real NSS 3.51 softoken (signalled by
/// <c>PKCS11_TEST_EXPECT_NSS_V240=1</c>). NSS 3.51 is the last release before 3.52 added the v3.0
/// <c>C_GetInterface</c> API, so it is a genuine pre-v3.0 module (it reports Cryptoki 2.20 and
/// implements v2.40 mechanisms), independent of SoftHSM.
/// These tests fail the leg loudly if the loaded module is not actually pre-v3.0, the same way
/// <see cref="SoftHsmV240ComplianceTests"/> does for SoftHSM 2.5.
/// </summary>
[Collection("Nss")]
public sealed class NssV240ComplianceTests(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    public static bool ExpectV240 =>
        string.Equals(Environment.GetEnvironmentVariable("PKCS11_TEST_EXPECT_NSS_V240"), "1", StringComparison.Ordinal)
        && NssBackendFixture.NssAvailable;

    /// <summary>
    /// NSS reports Cryptoki 2.20 in <c>C_GetInfo</c> through 3.51, although it implements v2.40
    /// mechanisms; 3.52 jumped straight to 3.0. What the leg needs is a pre-v3.0 module, so that is
    /// what is asserted.
    /// </summary>
    [Fact(SkipUnless = nameof(ExpectV240), Skip = "Requires " + nameof(ExpectV240))]
    public void Module_ReportsAPreV3CryptokiVersion()
        => Assert.Equal(2, _backend.Library.GetInfo().CryptokiVersion.Major);

    [Fact(SkipUnless = nameof(ExpectV240), Skip = "Requires " + nameof(ExpectV240))]
    public void Module_ExposesNoV3xSurface()
    {
        using var workspace = _backend.Library.OpenWorkspaceWithoutLogin(_backend.TokenLabel);

        // A v2.40 module negotiates neither the v3.0 message API nor the v3.2 additions.
        Assert.False(workspace.Session.SupportsMessageApi);
        Assert.False(workspace.Session.SupportsV32Api);
        Assert.False(workspace.Session.IsBoundThroughV3Interface);
    }

    [Fact(SkipUnless = nameof(ExpectV240), Skip = "Requires " + nameof(ExpectV240))]
    public void GetInterfaces_Throws_FunctionNotSupported()
    {
        // C_GetInterface does not exist before v3.0; the wrapper surfaces that as a typed CKR.
        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => _backend.Library.GetInterfaces());
        Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
    }
}
