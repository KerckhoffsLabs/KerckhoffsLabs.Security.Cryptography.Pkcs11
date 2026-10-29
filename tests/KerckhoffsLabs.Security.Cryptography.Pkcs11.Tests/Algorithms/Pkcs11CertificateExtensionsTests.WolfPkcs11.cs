using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// The DSA cases are [Obsolete] as GetDSAPrivateKey is (DSA is disallowed by FIPS 186-5); running them is deliberate.
#pragma warning disable KLPKCS11006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary><see cref="Pkcs11CertificateExtensions"/> over wolfPKCS11 — thin wrapper over <see cref="Pkcs11CertificateExtensionsTestCases"/>.</summary>
[Collection("WolfPkcs11")]
public sealed class Pkcs11CertificateExtensionsTests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly IPkcs11Backend _backend = backend;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void GetDSAPrivateKey_SignsForTheCertificate() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_GetDSAPrivateKey_SignsForTheCertificate);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void GetDSAPrivateKey_ReturnsNull_WithoutAKeyOnTheToken() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_GetDSAPrivateKey_ReturnsNull_WithoutAKeyOnTheToken);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.DerivedKeyReadbackAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 overrides a derived key's CKA_SENSITIVE and CKA_EXTRACTABLE from the base key")]
    public void GetECDiffieHellmanPrivateKey_AgreesWithTheCertificate() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_GetECDiffieHellmanPrivateKey_AgreesWithTheCertificate);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void GetECDiffieHellmanPrivateKey_ReturnsNull_WithoutAKeyOnTheToken() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_GetECDiffieHellmanPrivateKey_ReturnsNull_WithoutAKeyOnTheToken);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void EcGetters_FollowTheKeyUsage() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_EcGetters_FollowTheKeyUsage);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void EcGetters_RefuseAKeyOfAnotherType() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_EcGetters_RefuseAKeyOfAnotherType);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void EcGetters_RefuseAKeyOnAnotherCurve() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_EcGetters_RefuseAKeyOnAnotherCurve);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void EcGetters_RefuseExplicitCurveParameters() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_EcGetters_RefuseExplicitCurveParameters);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void GetMLDsaPrivateKey_SignsForTheCertificate() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_GetMLDsaPrivateKey_SignsForTheCertificate);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void GetMLDsaPrivateKey_ReturnsNull_WithoutAKeyOnTheToken() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_GetMLDsaPrivateKey_ReturnsNull_WithoutAKeyOnTheToken);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void GetMLDsaPrivateKey_RefusesAKeyOfAnotherParameterSet() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_GetMLDsaPrivateKey_RefusesAKeyOfAnotherParameterSet);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void GetMLKemPrivateKey_DecapsulatesForTheCertificate() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_GetMLKemPrivateKey_DecapsulatesForTheCertificate);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void GetMLKemPrivateKey_ReturnsNull_WithoutAKeyOnTheToken() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_GetMLKemPrivateKey_ReturnsNull_WithoutAKeyOnTheToken);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void GetSlhDsaPrivateKey_ReturnsNull_WithoutAKeyOnTheToken() => WithSession(Pkcs11CertificateExtensionsTestCases.Assert_GetSlhDsaPrivateKey_ReturnsNull_WithoutAKeyOnTheToken);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void GetSlhDsaPrivateKey_SignsForTheCertificate() => WithSession((session, supports) =>
        Pkcs11CertificateExtensionsTestCases.Assert_GetSlhDsaPrivateKey_SignsForTheCertificate(session, supports, _backend.SlhDsaTestParameterSet));

    private void WithSession(Action<Pkcs11Session, Func<CKM, bool>> body)
    {
        using var session = _backend.OpenSession();
        body(session, _backend.Supports);
    }
}
