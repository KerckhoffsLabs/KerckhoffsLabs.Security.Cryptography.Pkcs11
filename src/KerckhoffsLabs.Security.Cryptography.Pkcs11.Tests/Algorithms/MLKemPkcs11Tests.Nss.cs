using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>MLKemPkcs11Tests over NSS — thin wrapper over <see cref="MLKemPkcs11TestCases"/>.</summary>
[Collection("Nss")]
public sealed class MLKemPkcs11Tests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Ctor_NonMlKemKey_Throws() => MLKemPkcs11TestCases.Assert_Ctor_NonMlKemKey_Throws(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void EncapsulateDecapsulate_RoundTrips() => MLKemPkcs11TestCases.Assert_EncapsulateDecapsulate_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Decapsulate_BclEncapsulation_MatchesSharedSecret() =>
        MLKemPkcs11TestCases.Assert_Decapsulate_BclEncapsulation_MatchesSharedSecret(_backend, CkpMlKem.CKP_ML_KEM_768);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Encapsulate_GatedByDefault_Throws() => MLKemPkcs11TestCases.Assert_Encapsulate_GatedByDefault_Throws(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ExportEncapsulationKey_ReturnsStandardEncoding() => MLKemPkcs11TestCases.Assert_ExportEncapsulationKey_ReturnsStandardEncoding(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ExportDecapsulationKey_ThrowsInsecure() => MLKemPkcs11TestCases.Assert_ExportDecapsulationKey_ThrowsInsecure(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ExportPrivateSeed_ThrowsInsecure() => MLKemPkcs11TestCases.Assert_ExportPrivateSeed_ThrowsInsecure(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ExportPkcs8PrivateKey_ThrowsInsecure() => MLKemPkcs11TestCases.Assert_ExportPkcs8PrivateKey_ThrowsInsecure(_backend);
}
