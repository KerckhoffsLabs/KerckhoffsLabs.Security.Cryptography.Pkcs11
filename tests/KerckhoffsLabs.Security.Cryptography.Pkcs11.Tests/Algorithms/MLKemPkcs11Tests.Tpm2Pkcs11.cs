using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>MLKemPkcs11Tests over tpm2-pkcs11 — thin wrapper over <see cref="MLKemPkcs11TestCases"/>.</summary>
[Collection("Tpm2Pkcs11")]
public sealed class MLKemPkcs11Tests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture backend)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SecretKeyGenerationAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#564: C_GenerateKey is not implemented")]
    public void Ctor_NonMlKemKey_Throws() => MLKemPkcs11TestCases.Assert_Ctor_NonMlKemKey_Throws(_backend);

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    [MemberData(nameof(MLKemPkcs11TestCases.ParameterSets), MemberType = typeof(MLKemPkcs11TestCases))]
    public void EncapsulateDecapsulate_RoundTrips(CkpMlKem parameterSet) =>
        MLKemPkcs11TestCases.Assert_EncapsulateDecapsulate_RoundTrips(_backend, parameterSet);

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    [MemberData(nameof(MLKemPkcs11TestCases.ParameterSets), MemberType = typeof(MLKemPkcs11TestCases))]
    public void Decapsulate_BclEncapsulation_MatchesSharedSecret(CkpMlKem parameterSet) =>
        MLKemPkcs11TestCases.Assert_Decapsulate_BclEncapsulation_MatchesSharedSecret(_backend, parameterSet);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Encapsulate_GatedByDefault_Throws() => MLKemPkcs11TestCases.Assert_Encapsulate_GatedByDefault_Throws(_backend);

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    [MemberData(nameof(MLKemPkcs11TestCases.ParameterSets), MemberType = typeof(MLKemPkcs11TestCases))]
    public void ExportEncapsulationKey_ReturnsStandardEncoding(CkpMlKem parameterSet) =>
        MLKemPkcs11TestCases.Assert_ExportEncapsulationKey_ReturnsStandardEncoding(_backend, parameterSet);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void ExportDecapsulationKey_ThrowsInsecure() => MLKemPkcs11TestCases.Assert_ExportDecapsulationKey_ThrowsInsecure(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void ExportPrivateSeed_ThrowsInsecure() => MLKemPkcs11TestCases.Assert_ExportPrivateSeed_ThrowsInsecure(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void ExportPkcs8PrivateKey_ThrowsInsecure() => MLKemPkcs11TestCases.Assert_ExportPkcs8PrivateKey_ThrowsInsecure(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Decapsulate_CachesValueLenQuirkPerLibrary() =>
        MLKemPkcs11TestCases.Assert_Decapsulate_CachesValueLenQuirkPerLibrary(_backend, expectedOmitsValueLen: false);
}
