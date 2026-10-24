using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// The DSA cases are [Obsolete] as GetDSAPrivateKey is (DSA is disallowed by FIPS 186-5); running them is deliberate.
#pragma warning disable KLPKCS11006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary><see cref="Pkcs11CertificateExtensions"/> over Craton HSM — thin wrapper over <see cref="Pkcs11CertificateExtensionsTestCases"/>.</summary>
[Collection("CratonHsm")]
public sealed class Pkcs11CertificateExtensionsTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly IPkcs11Backend _backend = backend;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void GetDSAPrivateKey_SignsForTheCertificate() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_GetDSAPrivateKey_SignsForTheCertificate);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void GetDSAPrivateKey_ReturnsNull_WithoutAKeyOnTheToken() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_GetDSAPrivateKey_ReturnsNull_WithoutAKeyOnTheToken);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void GetECDiffieHellmanPrivateKey_AgreesWithTheCertificate() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_GetECDiffieHellmanPrivateKey_AgreesWithTheCertificate);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void GetECDiffieHellmanPrivateKey_ReturnsNull_WithoutAKeyOnTheToken() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_GetECDiffieHellmanPrivateKey_ReturnsNull_WithoutAKeyOnTheToken);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void EcGetters_FollowTheKeyUsage() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_EcGetters_FollowTheKeyUsage);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void EcGetters_RefuseAKeyOfAnotherType() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_EcGetters_RefuseAKeyOfAnotherType);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void EcGetters_RefuseAKeyOnAnotherCurve() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_EcGetters_RefuseAKeyOnAnotherCurve);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void EcGetters_RefuseExplicitCurveParameters() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_EcGetters_RefuseExplicitCurveParameters);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void GetMLDsaPrivateKey_SignsForTheCertificate() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_GetMLDsaPrivateKey_SignsForTheCertificate);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void GetMLDsaPrivateKey_ReturnsNull_WithoutAKeyOnTheToken() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_GetMLDsaPrivateKey_ReturnsNull_WithoutAKeyOnTheToken);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void GetMLDsaPrivateKey_RefusesAKeyOfAnotherParameterSet() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_GetMLDsaPrivateKey_RefusesAKeyOfAnotherParameterSet);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void GetMLKemPrivateKey_DecapsulatesForTheCertificate() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_GetMLKemPrivateKey_DecapsulatesForTheCertificate);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void GetMLKemPrivateKey_ReturnsNull_WithoutAKeyOnTheToken() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_GetMLKemPrivateKey_ReturnsNull_WithoutAKeyOnTheToken);

    // SHA2-128s: Craton HSM implements SHA2-128s and SHA2-256s only (see CratonHsmBackendFixture.SlhDsaTestParameterSet).
    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void GetSlhDsaPrivateKey_SignsForTheCertificate() => WithSession((session, supports) =>
        Pkcs11CertificateExtensionsTestCases.Assert_GetSlhDsaPrivateKey_SignsForTheCertificate(session, supports, _backend.SlhDsaTestParameterSet));

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void GetSlhDsaPrivateKey_ReturnsNull_WithoutAKeyOnTheToken() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_GetSlhDsaPrivateKey_ReturnsNull_WithoutAKeyOnTheToken);

    private void WithSession(Action<Pkcs11Session, Func<CKM, bool>> body)
    {
        using var session = _backend.OpenSession();
        body(session, _backend.Supports);
    }
}
