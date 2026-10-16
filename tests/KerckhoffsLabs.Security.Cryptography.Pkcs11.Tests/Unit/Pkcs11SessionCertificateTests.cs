using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// Certificates through the same lookup rules as keys (<see cref="Pkcs11Session.OpenCertificate(string)"/>
/// and its siblings): only X.509 certificate objects match, exactly one must, and the certificate and its
/// key find each other by <c>CKA_ID</c>. Runs on the in-process token, where duplicates are easy to set up.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11SessionCertificateTests : IDisposable
{
    private const string Label = "tls-server";
    private static readonly byte[] KeyId = [0x0C, 0x0D];
    private static readonly byte[] OtherId = [0x0E];

    private readonly Pkcs11Library _library = ManagedToken.NewLibrary();
    private readonly Pkcs11Session _session;

    public Pkcs11SessionCertificateTests() => _session = ManagedToken.OpenSession(_library);

    public void Dispose()
    {
        _session.Dispose();
        _library.Dispose();
    }

    private static X509Certificate2 SelfSigned(string subject)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest($"CN={subject}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private Pkcs11Certificate Import(string subject, string label, byte[] id)
    {
        using X509Certificate2 certificate = SelfSigned(subject);
        return _session.ImportCertificate(certificate, label, id);
    }

    private Pkcs11Key GenerateEcPair(byte[] id)
    {
        using var pub = ObjectTemplate.ForPublicKey(CKK.CKK_EC).EcParams(Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams())
            .Verify().Label(Label).Id(id).Build();
        using var priv = ObjectTemplate.ForPrivateKey(CKK.CKK_EC).Sign().Label(Label).Id(id).Build();
        return _session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), pub, priv);
    }

    // === Import ==============================================================

    [Fact]
    public void ImportCertificate_StoresTheCertificateWithItsLabelAndId()
    {
        using X509Certificate2 original = SelfSigned("import");
        using Pkcs11Certificate stored = _session.ImportCertificate(original, Label, KeyId);

        Assert.Equal(original.RawData, stored.Certificate.RawData);
        Assert.Equal(Label, stored.Label);
        Assert.Equal(KeyId, stored.Id.ToArray());

        using var attrs = _session.Core.GetAttributeValue(stored.Handle,
            [CKA.CKA_CERTIFICATE_TYPE, CKA.CKA_SUBJECT, CKA.CKA_ISSUER, CKA.CKA_TOKEN]);
        Assert.Equal((ulong)CKC.CKC_X_509, attrs[0].GetValueAsUlong());
        Assert.Equal(original.SubjectName.RawData, attrs[1].GetValueAsByteArray());
        Assert.Equal(original.IssuerName.RawData, attrs[2].GetValueAsByteArray());
        Assert.False(attrs[3].GetValueAsBool());
    }

    [Fact]
    public void ImportCertificate_InvalidArguments_AreRejected()
    {
        using X509Certificate2 certificate = SelfSigned("args");

        Assert.Throws<ArgumentNullException>(() => _session.ImportCertificate(null!, Label, KeyId));
        Assert.Throws<ArgumentNullException>(() => _session.ImportCertificate(certificate, null!, KeyId));
        var ex = Assert.Throws<ArgumentException>(() => _session.ImportCertificate(certificate, Label, ReadOnlySpan<byte>.Empty));
        Assert.Equal("id", ex.ParamName);
    }

    // === One certificate =====================================================

    [Fact]
    public void OpenByLabelIdOrFilter_FindsTheCertificate()
    {
        using (Import("one", Label, KeyId)) { }

        using Pkcs11Certificate byLabel = _session.OpenCertificate(Label);
        using Pkcs11Certificate byId = _session.OpenCertificate(KeyId);
        using ObjectTemplate filter = ObjectTemplate.Empty().Label(Label).Id(KeyId).Build();
        using Pkcs11Certificate byFilter = _session.OpenCertificate(filter);

        Assert.Equal(byLabel.Certificate.RawData, byId.Certificate.RawData);
        Assert.Equal(byLabel.Certificate.RawData, byFilter.Certificate.RawData);
    }

    // A key with the certificate's label and id is not a certificate.
    [Fact]
    public void KeySharingLabelAndId_IsIgnored()
    {
        using (GenerateEcPair(KeyId)) { }
        using (Import("one", Label, KeyId)) { }

        using Pkcs11Certificate byLabel = _session.OpenCertificate(Label);
        using Pkcs11Certificate byId = _session.OpenCertificate(KeyId);
        Assert.Equal("CN=one", byLabel.Certificate.Subject);
        Assert.Equal("CN=one", byId.Certificate.Subject);
    }

    // Pkcs11Certificate holds an X509Certificate2, so other certificate types are not in the family.
    [Fact]
    public void NonX509CertificateSharingTheLabel_IsIgnored()
    {
        using (Import("one", Label, KeyId)) { }
        using var attributeCertificate = ObjectTemplate.ForCertificate(CKC.CKC_X_509_ATTR_CERT)
            .Label(Label).Value([0x30, 0x00]).Build();
        _session.Core.CreateObject([.. attributeCertificate.Attributes]);

        using Pkcs11Certificate certificate = _session.OpenCertificate(Label);
        Assert.Equal("CN=one", certificate.Certificate.Subject);
        using var all = _session.FindCertificates();
        Assert.Single(all);
    }

    // === Ambiguity ===========================================================

    [Fact]
    public void TwoCertificatesSharingTheLabel_AreRefused_AndAnIdResolvesThem()
    {
        using (Import("one", Label, KeyId)) { }
        using (Import("two", Label, OtherId)) { }

        var ex = Assert.Throws<Pkcs11AmbiguousObjectException>(() => _session.OpenCertificate(Label));
        Assert.Equal(CKR.CKR_OK, ex.ReturnValue);
        Assert.Throws<Pkcs11AmbiguousObjectException>(() => _session.TryOpenCertificate(Label, out _));

        using Pkcs11Certificate two = _session.OpenCertificate(OtherId);
        Assert.Equal("CN=two", two.Certificate.Subject);
    }

    // === No certificate ======================================================

    [Fact]
    public void NoMatch_OpenThrowsNotFound_AndTryOpenReturnsFalse()
    {
        using (GenerateEcPair(KeyId)) { }

        var ex = Assert.Throws<Pkcs11ObjectNotFoundException>(() => _session.OpenCertificate(Label));
        Assert.Contains(Label, ex.Message);
        Assert.Throws<Pkcs11ObjectNotFoundException>(() => _session.OpenCertificate(KeyId));
        Assert.False(_session.TryOpenCertificate(Label, out Pkcs11Certificate? byLabel));
        Assert.Null(byLabel);
        Assert.False(_session.TryOpenCertificate(KeyId, out _));
        using ObjectTemplate filter = ObjectTemplate.Empty().Label(Label).Build();
        Assert.False(_session.TryOpenCertificate(filter, out _));
    }

    // === Find ================================================================

    [Fact]
    public void FindCertificates_Filter_ReturnsOnlyTheMatches()
    {
        using (Import("one", Label, KeyId)) { }
        using (Import("two", "other", OtherId)) { }

        using ObjectTemplate filter = ObjectTemplate.Empty().Label(Label).Build();
        using var matched = _session.FindCertificates(filter);
        using var all = _session.FindCertificates();

        Assert.Equal("CN=one", Assert.Single(matched).Certificate.Subject);
        Assert.Equal(2, all.Count);
    }

    [Fact]
    public void FindCertificates_BySubject_IsFilteredOnTheToken()
    {
        using X509Certificate2 one = SelfSigned("one");
        using (_session.ImportCertificate(one, Label, KeyId)) { }
        using (Import("two", Label, OtherId)) { }

        using ObjectTemplate filter = ObjectTemplate.Empty().Attribute(CKA.CKA_SUBJECT, one.SubjectName.RawData).Build();
        using var matched = _session.FindCertificates(filter);

        Assert.Equal(KeyId, Assert.Single(matched).Id.ToArray());
    }

    // === Filters that contradict the family ==================================

    [Theory]
    [InlineData(CKO.CKO_PRIVATE_KEY)]
    [InlineData(CKO.CKO_DATA)]
    public void FilterNamingAnotherClass_IsRejected(CKO objectClass)
    {
        using ObjectTemplate filter = ObjectTemplate.Empty().Label(Label).Attribute(CKA.CKA_CLASS, (ulong)objectClass).Build();

        Assert.Equal("filter", Assert.Throws<ArgumentException>(() => _session.OpenCertificate(filter)).ParamName);
        Assert.Equal("filter", Assert.Throws<ArgumentException>(() => _session.FindCertificates(filter)).ParamName);
    }

    [Fact]
    public void FilterNamingAnotherCertificateType_IsRejected()
    {
        using ObjectTemplate filter = ObjectTemplate.Empty()
            .Attribute(CKA.CKA_CERTIFICATE_TYPE, (ulong)CKC.CKC_WTLS).Build();

        Assert.Equal("filter", Assert.Throws<ArgumentException>(() => _session.TryOpenCertificate(filter, out _)).ParamName);
    }

    // === Certificate <-> key, by CKA_ID ======================================

    [Fact]
    public void KeyAndCertificate_FindEachOther()
    {
        using Pkcs11Key key = GenerateEcPair(KeyId);
        using (Import("one", Label, KeyId)) { }

        using Pkcs11Certificate? certificate = key.GetCertificate();
        Assert.NotNull(certificate);
        Assert.Equal("CN=one", certificate.Certificate.Subject);

        using Pkcs11Key? privateKey = certificate.GetPrivateKey();
        Assert.NotNull(privateKey);
        Assert.Equal(KeyId, privateKey.Id.ToArray());
    }

    [Fact]
    public void GetCertificate_NoCertificateOrNoId_IsNull()
    {
        using Pkcs11Key withId = GenerateEcPair(KeyId);
        Assert.Null(withId.GetCertificate());

        using Pkcs11Key withoutId = _session.GenerateAesKey();
        Assert.Null(withoutId.GetCertificate());
    }

    [Fact]
    public void GetCertificate_TwoCertificatesWithTheKeysId_IsRefused()
    {
        using Pkcs11Key key = GenerateEcPair(KeyId);
        using (Import("one", Label, KeyId)) { }
        using (Import("two", "other", KeyId)) { }

        Assert.Throws<Pkcs11AmbiguousObjectException>(() => key.GetCertificate());
    }

    [Fact]
    public void InvalidArguments_AreRejected()
    {
        Assert.Throws<ArgumentNullException>(() => _session.OpenCertificate((string)null!));
        Assert.Throws<ArgumentNullException>(() => _session.OpenCertificate((ObjectTemplate)null!));
        Assert.Throws<ArgumentNullException>(() => _session.FindCertificates(null!));
        Assert.Throws<ArgumentException>(() => _session.OpenCertificate(ReadOnlySpan<byte>.Empty));
        Assert.Throws<ArgumentException>(() => _session.TryOpenCertificate(ReadOnlySpan<byte>.Empty, out _));
    }
}
