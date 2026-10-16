using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>RC2Pkcs11Tests over NSS — thin wrapper over <see cref="RC2Pkcs11TestCases"/>.</summary>
[Collection("Nss")]
public sealed class RC2Pkcs11Tests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    // NSS's CKM_RC2_ECB rejects the spec's CK_RC2_PARAMS (it wants CK_RC2_CBC_PARAMS), so the ECB
    // round-trip skips; RC2-CBC is exercised. See NssBackendFixture.SupportsRc2Ecb.

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Ctor_NonRc2Key_Throws() => RC2Pkcs11TestCases.Assert_Ctor_NonRc2Key_Throws(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void EncryptCbc_Pkcs7_GatedByDefault_Throws() => RC2Pkcs11TestCases.Assert_EncryptCbc_Pkcs7_GatedByDefault_Throws(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void EncryptEcb_GatedByDefault_Throws() => RC2Pkcs11TestCases.Assert_EncryptEcb_GatedByDefault_Throws(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void EncryptCbc_Pkcs7_AllowInsecure_MatchesBcl() => RC2Pkcs11TestCases.Assert_EncryptCbc_Pkcs7_AllowInsecure_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void EncryptCbc_NonePadding_AllowInsecure_MatchesBcl() => RC2Pkcs11TestCases.Assert_EncryptCbc_NonePadding_AllowInsecure_MatchesBcl(_backend);

    // NSS is the only real backend that implements RC2-CBC (SoftHSM/OpenCryptoki don't implement RC2
    // at all), so it's the only place a reduced RFC 2268 effective-key-bits round-trip can be
    // exercised against real token crypto instead of the BCL, which cannot represent this case at all.
    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void EncryptCbc_ReducedEffectiveKeySize_MatchesKnownAnswer() => RC2Pkcs11TestCases.Assert_EncryptCbc_ReducedEffectiveKeySize_MatchesKnownAnswer(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.Rc2EcbAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.Rc2EcbAvailable))]
    public void EncryptEcb_AllowInsecure_MatchesBcl() => RC2Pkcs11TestCases.Assert_EncryptEcb_AllowInsecure_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void EncryptCbc_UnsupportedPadding_Throws() => RC2Pkcs11TestCases.Assert_EncryptCbc_UnsupportedPadding_Throws(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void GenerateIV_ProducesBlockSizedIv() => RC2Pkcs11TestCases.Assert_GenerateIV_ProducesBlockSizedIv(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ManagedKeyAndStreamingSurface_NotSupported() => RC2Pkcs11TestCases.Assert_ManagedKeyAndStreamingSurface_NotSupported(_backend);
}
