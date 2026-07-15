using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>NSS counterpart of Pkcs11KeyMechanismTests_SoftHsm (shared Pkcs11KeyMechanismCases).</summary>
[Collection("Nss")]
public sealed class Pkcs11KeyMechanismTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;
    public static bool Available => NssBackendFixture.NssAvailable;

    // These generate a token (persistent) key; NSS's generic token is write-protected, so they skip.
    public static bool TokenObjects => NssBackendFixture.TokenObjectsAvailable;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspaceWithoutLogin(_backend.TokenLabel);

    [ConditionalFact(nameof(Available))]
    public void RsaPkcs_SignVerify_RoundTrip()
    {
        using var workspace = OpenWorkspace();
        Pkcs11KeyMechanismCases.Assert_RsaSignVerify_RoundTrips(workspace);
    }

    [ConditionalFact(nameof(TokenObjects))]
    public void AesCbc_EncryptDecrypt_RoundTrip()
    {
        using var workspace = OpenWorkspace();
        Pkcs11KeyMechanismCases.Assert_AesCbcEncryptDecrypt_RoundTrips(workspace);
    }

    [ConditionalFact(nameof(TokenObjects))]
    public void AesKeyWrap_WrapUnwrap_RoundTrip()
    {
        using var workspace = OpenWorkspace();
        Pkcs11KeyMechanismCases.Assert_AesKeyWrapUnwrap_RoundTrips(workspace);
    }
}
