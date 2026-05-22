using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Digest;

/// <summary>
/// Workspace-facade digest tests: verify <see cref="Pkcs11Workspace.Digest"/> delegates to
/// the session, firing the insecure-mechanism gate and null-argument guard in managed code
/// before any native call. Backend digest correctness lives in <see cref="DigestSha2Tests"/>
/// and <see cref="DigestMd5Sha1Tests"/>.
/// </summary>
[Collection("Mock")]
public sealed class WorkspaceDigestTests(MockBackendFixture backend)
{
    private readonly MockBackendFixture _backend = backend;

    [Fact]
    public void Digest_Sha1_ThrowsInsecureOperationException()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        var mechanism = new Mechanism(CKM.CKM_SHA_1);
        byte[] data = System.Text.Encoding.UTF8.GetBytes("hello");

        // InsecureOperationException fires in managed code before C_DigestInit,
        // which proves workspace.Digest delegates correctly to _session.Digest.
        Assert.Throws<InsecureOperationException>(() =>
            workspace.Digest(mechanism, data));
    }

    [Fact]
    public void Digest_NullMechanism_Throws()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        Assert.Throws<ArgumentNullException>(() =>
            workspace.Digest(mechanism: null!, []));
    }
}
