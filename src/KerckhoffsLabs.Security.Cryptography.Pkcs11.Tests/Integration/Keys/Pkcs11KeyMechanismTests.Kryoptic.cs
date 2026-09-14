using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>Kryoptic counterpart of Pkcs11KeyMechanismTests_SoftHsm (shared Pkcs11KeyMechanismCases).</summary>
[Collection("Kryoptic")]
public sealed class Pkcs11KeyMechanismTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void RsaPkcs_SignVerify_RoundTrip()
    {
        using var workspace = OpenWorkspace();
        Pkcs11KeyMechanismCases.Assert_RsaSignVerify_RoundTrips(workspace);
    }

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void AesCbc_EncryptDecrypt_RoundTrip()
    {
        using var workspace = OpenWorkspace();
        Pkcs11KeyMechanismCases.Assert_AesCbcEncryptDecrypt_RoundTrips(workspace);
    }

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void AesKeyWrap_WrapUnwrap_RoundTrip()
    {
        using var workspace = OpenWorkspace();
        Pkcs11KeyMechanismCases.Assert_AesKeyWrapUnwrap_RoundTrips(workspace);
    }
}
