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

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(MLKemPkcs11TestCases.ParameterSets), MemberType = typeof(MLKemPkcs11TestCases))]
    public void EncapsulateDecapsulate_RoundTrips(CkpMlKem parameterSet) =>
        MLKemPkcs11TestCases.Assert_EncapsulateDecapsulate_RoundTrips(_backend, parameterSet);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(MLKemPkcs11TestCases.ParameterSets), MemberType = typeof(MLKemPkcs11TestCases))]
    public void Decapsulate_BclEncapsulation_MatchesSharedSecret(CkpMlKem parameterSet) =>
        MLKemPkcs11TestCases.Assert_Decapsulate_BclEncapsulation_MatchesSharedSecret(_backend, parameterSet);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Encapsulate_GatedByDefault_Throws() => MLKemPkcs11TestCases.Assert_Encapsulate_GatedByDefault_Throws(_backend);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(MLKemPkcs11TestCases.ParameterSets), MemberType = typeof(MLKemPkcs11TestCases))]
    public void ExportEncapsulationKey_ReturnsStandardEncoding(CkpMlKem parameterSet) =>
        MLKemPkcs11TestCases.Assert_ExportEncapsulationKey_ReturnsStandardEncoding(_backend, parameterSet);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ExportDecapsulationKey_ThrowsInsecure() => MLKemPkcs11TestCases.Assert_ExportDecapsulationKey_ThrowsInsecure(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ExportPrivateSeed_ThrowsInsecure() => MLKemPkcs11TestCases.Assert_ExportPrivateSeed_ThrowsInsecure(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ExportPkcs8PrivateKey_ThrowsInsecure() => MLKemPkcs11TestCases.Assert_ExportPkcs8PrivateKey_ThrowsInsecure(_backend);
}
