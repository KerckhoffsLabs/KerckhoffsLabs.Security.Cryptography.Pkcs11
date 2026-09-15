using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Hermetic coverage for <see cref="Pkcs11Workspace.DeriveSharedSecretEcdh(Pkcs11Key, ReadOnlySpan{byte}, int, CKD)"/>'s
/// <c>CKD_NULL</c> secure-defaults gate: <c>CKD_NULL</c> applies no KDF to the raw
/// ECDH shared secret, so the derived AES key becomes the raw x-coordinate (or a token-chosen
/// truncation of it) — NIST SP 800-56A forbids this. The gate runs before any native call (before
/// even constructing <c>CkmEcdh1DeriveParams</c>), so it's exercised here with a dummy handle and
/// peer point rather than a real ECDH round trip.
/// </summary>
[Collection("Mock")]
public sealed class DeriveSharedSecretEcdhTests_Mock(MockBackendFixture backend)
{
    private readonly MockBackendFixture _backend = backend;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    private static Pkcs11Key DummyEcKey(Pkcs11Workspace workspace) =>
        new(workspace, privateHandle: new ObjectHandle(1), publicHandle: ObjectHandle.Invalid,
            keyType: CKK.CKK_EC, label: null, id: [], ownedLibrary: null, ownsWorkspace: false);

    [Fact]
    public void CkdNull_GatedByDefault_Throws()
    {
        using var workspace = OpenWorkspace();
        using var key = DummyEcKey(workspace);

        var ex = Assert.Throws<InsecureOperationException>(
            () => workspace.DeriveSharedSecretEcdh(key, new byte[4], kdf: CKD.CKD_NULL));
        Assert.Equal(CKM.CKM_ECDH1_DERIVE, ex.Mechanism);
    }

    [Fact]
    public void CkdNull_AllowInsecureScope_BypassesGate()
    {
        using var workspace = OpenWorkspace();
        using var key = DummyEcKey(workspace);

        using (workspace.AllowInsecureScope())
        {
            // The gate is bypassed; the call reaches CkmEcdh1DeriveParams / the native derive, which
            // fails on the dummy handle and malformed peer point — the point is it is NOT the gate.
            Exception? ex = Record.Exception(
                () => workspace.DeriveSharedSecretEcdh(key, new byte[4], kdf: CKD.CKD_NULL));
            Assert.False(ex is InsecureOperationException, "AllowInsecure should bypass the CKD_NULL gate.");
        }
    }

    [Fact]
    public void DefaultKdf_DoesNotTriggerTheGate()
    {
        using var workspace = OpenWorkspace();
        using var key = DummyEcKey(workspace);

        // Default CKD_SHA256_KDF must never trip the CKD_NULL gate, regardless of AllowInsecure.
        Exception? ex = Record.Exception(() => workspace.DeriveSharedSecretEcdh(key, new byte[4]));
        Assert.False(ex is InsecureOperationException, "The default KDF must not trigger the CKD_NULL gate.");
    }
}
