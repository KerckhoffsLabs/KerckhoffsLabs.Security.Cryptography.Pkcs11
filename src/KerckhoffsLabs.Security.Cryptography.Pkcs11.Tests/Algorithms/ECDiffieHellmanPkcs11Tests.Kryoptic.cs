using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>ECDiffieHellmanPkcs11Tests over Kryoptic — thin wrapper over <see cref="ECDiffieHellmanPkcs11TestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class ECDiffieHellmanPkcs11Tests_Kryoptic(KryopticBackendFixture f)
{
    private readonly KryopticBackendFixture _backend = f;
    public static bool KryopticAvailable => KryopticBackendFixture.KryopticAvailable;

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Ctor_NonEcKey_Throws() => ECDiffieHellmanPkcs11TestCases.Assert_Ctor_NonEcKey_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void DeriveKeyFromHash_AgreesWithBcl() => ECDiffieHellmanPkcs11TestCases.Assert_DeriveKeyFromHash_AgreesWithBcl(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void DeriveKeyFromHash_WithPrependAppend_AgreesWithBcl() => ECDiffieHellmanPkcs11TestCases.Assert_DeriveKeyFromHash_WithPrependAppend_AgreesWithBcl(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void DeriveKeyFromHmac_AgreesWithBcl() => ECDiffieHellmanPkcs11TestCases.Assert_DeriveKeyFromHmac_AgreesWithBcl(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void DeriveKeyFromHmac_NullKey_UsesSecret_AgreesWithBcl() => ECDiffieHellmanPkcs11TestCases.Assert_DeriveKeyFromHmac_NullKey_UsesSecret_AgreesWithBcl(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void DeriveRawSecretAgreement_MatchesBcl() => ECDiffieHellmanPkcs11TestCases.Assert_DeriveRawSecretAgreement_MatchesBcl(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void DeriveKeyMaterial_AgreesWithBcl() => ECDiffieHellmanPkcs11TestCases.Assert_DeriveKeyMaterial_AgreesWithBcl(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void PublicKey_ExportsTokenPoint() => ECDiffieHellmanPkcs11TestCases.Assert_PublicKey_ExportsTokenPoint(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void DeriveKeyTls_NotSupported() => ECDiffieHellmanPkcs11TestCases.Assert_DeriveKeyTls_NotSupported(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void ExportParameters_Private_ThrowsInsecure() => ECDiffieHellmanPkcs11TestCases.Assert_ExportParameters_Private_ThrowsInsecure(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void ImportParameters_NotSupported() => ECDiffieHellmanPkcs11TestCases.Assert_ImportParameters_NotSupported(_backend);
}
