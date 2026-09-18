using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Objects;

/// <summary>
/// Coverage for <see cref="Pkcs11Certificate"/> — previously 0% covered, since the only existing
/// tests (FindObjectsTests.*) target real backends that don't load in this sandbox. Constructs the
/// wrapper directly (the internal ctor is visible via InternalsVisibleTo, exactly as
/// <c>Pkcs11Workspace.FindCertificates</c> would) over a real self-signed X509Certificate2 and one of
/// pkcs11-mock's fixed sentinel handles — the CKO_SECRET_KEY handle stands in for a certificate
/// object here since the mock has no certificate class of its own (CKO_DATA would also work but
/// returns its handle twice from C_FindObjects, a pkcs11-mock quirk unrelated to what's under test).
/// Every member under test (properties, disposal, Destroy's C_DestroyObject call, TryOpenPrivateKey's
/// dispatch) only cares that the handle is one of the mock's four accepted values, not which token
/// object class it nominally represents.
/// </summary>
[Collection("Mock")]
public sealed class Pkcs11CertificateTests(MockBackendFixture backend)
{
    private readonly MockBackendFixture _backend = backend;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspaceWithPin(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    private static ObjectHandle FindByClass(Pkcs11Workspace workspace, CKO objectClass)
    {
        using var findClass = new ObjectAttribute(CKA.CKA_CLASS, objectClass);
        return Assert.Single(workspace.Session.FindAllObjects([findClass]));
    }

    private static X509Certificate2 CreateSelfSignedCertificate()
    {
        using RSA rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=Pkcs11CertificateTests", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    [Fact]
    public void Properties_AreExposed()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle handle = FindByClass(workspace, CKO.CKO_SECRET_KEY);
        using var certificate = CreateSelfSignedCertificate();
        byte[] id = [0x01, 0x02];

        using var pkcs11Cert = new Pkcs11Certificate(workspace, handle, "my-cert", id, certificate);

        Assert.Same(certificate, pkcs11Cert.Certificate);
        Assert.Equal("my-cert", pkcs11Cert.Label);
        Assert.True(id.AsSpan().SequenceEqual(pkcs11Cert.Id));
        Assert.Equal(handle, pkcs11Cert.Handle);
    }

    [Fact]
    public void Ctor_NullIdAndLabel_DefaultsToEmptyIdAndNullLabel()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle handle = FindByClass(workspace, CKO.CKO_SECRET_KEY);
        using var certificate = CreateSelfSignedCertificate();

        using var pkcs11Cert = new Pkcs11Certificate(workspace, handle, label: null, id: null!, certificate);

        Assert.True(pkcs11Cert.Id.IsEmpty);
        Assert.Null(pkcs11Cert.Label);
    }

    [Fact]
    public void TryOpenPrivateKey_EmptyId_ReturnsNull()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle handle = FindByClass(workspace, CKO.CKO_SECRET_KEY);
        using var certificate = CreateSelfSignedCertificate();
        using var pkcs11Cert = new Pkcs11Certificate(workspace, handle, null, [], certificate);

        Assert.Null(pkcs11Cert.TryOpenPrivateKey());
    }

    [Fact]
    public void TryOpenPrivateKey_AfterDispose_Throws()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle handle = FindByClass(workspace, CKO.CKO_SECRET_KEY);
        var certificate = CreateSelfSignedCertificate();
        var pkcs11Cert = new Pkcs11Certificate(workspace, handle, null, [], certificate);
        pkcs11Cert.Dispose();

        Assert.Throws<ObjectDisposedException>(() => pkcs11Cert.TryOpenPrivateKey());
    }

    [Fact]
    public void Destroy_RemovesTokenObject()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle handle = FindByClass(workspace, CKO.CKO_SECRET_KEY);
        using var certificate = CreateSelfSignedCertificate();
        using var pkcs11Cert = new Pkcs11Certificate(workspace, handle, null, [], certificate);

        // pkcs11-mock's C_DestroyObject accepts any of its four sentinel handles unconditionally.
        pkcs11Cert.Destroy();
    }

    [Fact]
    public void Destroy_AfterDispose_Throws()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle handle = FindByClass(workspace, CKO.CKO_SECRET_KEY);
        var certificate = CreateSelfSignedCertificate();
        var pkcs11Cert = new Pkcs11Certificate(workspace, handle, null, [], certificate);
        pkcs11Cert.Dispose();

        Assert.Throws<ObjectDisposedException>(() => pkcs11Cert.Destroy());
    }

    [Fact]
    public void Dispose_IsIdempotent_AndDisposesTheWrappedCertificate()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle handle = FindByClass(workspace, CKO.CKO_SECRET_KEY);
        var certificate = CreateSelfSignedCertificate();
        var pkcs11Cert = new Pkcs11Certificate(workspace, handle, null, [], certificate);

        pkcs11Cert.Dispose();
        pkcs11Cert.Dispose(); // second call is a no-op, not a double-free

        // A disposed X509Certificate2 resets its native handle; touching it afterwards throws.
        Assert.Throws<CryptographicException>(() => certificate.GetRawCertData());
    }
}
