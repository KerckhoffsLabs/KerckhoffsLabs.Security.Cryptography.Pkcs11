using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>MLKemPkcs11Tests over SoftHsm — thin wrapper over <see cref="MLKemPkcs11TestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class MLKemPkcs11Tests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ctor_NonMlKemKey_Throws() => MLKemPkcs11TestCases.Assert_Ctor_NonMlKemKey_Throws(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncapsulateDecapsulate_RoundTrips() => MLKemPkcs11TestCases.Assert_EncapsulateDecapsulate_RoundTrips(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Decapsulate_BclEncapsulation_MatchesSharedSecret() =>
        MLKemPkcs11TestCases.Assert_Decapsulate_BclEncapsulation_MatchesSharedSecret(_backend, CkpMlKem.CKP_ML_KEM_768);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Encapsulate_GatedByDefault_Throws() => MLKemPkcs11TestCases.Assert_Encapsulate_GatedByDefault_Throws(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ExportEncapsulationKey_ReturnsStandardEncoding() => MLKemPkcs11TestCases.Assert_ExportEncapsulationKey_ReturnsStandardEncoding(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ExportDecapsulationKey_ThrowsInsecure() => MLKemPkcs11TestCases.Assert_ExportDecapsulationKey_ThrowsInsecure(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ExportPrivateSeed_ThrowsInsecure() => MLKemPkcs11TestCases.Assert_ExportPrivateSeed_ThrowsInsecure(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ExportPkcs8PrivateKey_ThrowsInsecure() => MLKemPkcs11TestCases.Assert_ExportPkcs8PrivateKey_ThrowsInsecure(_backend);
}
