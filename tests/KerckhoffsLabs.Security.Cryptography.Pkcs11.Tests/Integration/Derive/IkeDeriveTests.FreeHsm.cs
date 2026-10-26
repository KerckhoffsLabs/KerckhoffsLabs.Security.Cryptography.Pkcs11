using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Derive;

/// <summary>The IKE-derive family over FreeHSM — thin wrapper over <see cref="IkeDeriveTestCases"/>.</summary>
[Collection("FreeHsm")]
public sealed class IkeDeriveTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void IkePrf_MatchesReference() => IkeDeriveTestCases.Assert_IkePrf_MatchesReference(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Ike1Prf_MatchesReference() => IkeDeriveTestCases.Assert_Ike1Prf_MatchesReference(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Ike1ExtendedDerive_MatchesReference() => IkeDeriveTestCases.Assert_Ike1ExtendedDerive_MatchesReference(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Ike2PrfPlusDerive_MatchesReference() => IkeDeriveTestCases.Assert_Ike2PrfPlusDerive_MatchesReference(_backend);

    // Sign-probe variants: same derivations, verified without reading CKA_VALUE — see
    // IkeDeriveTestCases's class doc comment for why this is a useful cross-check on its own.

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void IkePrf_MatchesBclViaSignProbe() => IkeDeriveTestCases.Assert_IkePrf_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Ike1Prf_MatchesBclViaSignProbe() => IkeDeriveTestCases.Assert_Ike1Prf_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Ike1ExtendedDerive_MatchesBclViaSignProbe() => IkeDeriveTestCases.Assert_Ike1ExtendedDerive_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Ike2PrfPlusDerive_MatchesBclViaSignProbe() => IkeDeriveTestCases.Assert_Ike2PrfPlusDerive_MatchesBclViaSignProbe(_backend);

    // Not shared with NSS: NSS's sftkike.c never checks the base key's CKA_KEY_TYPE at all, so this
    // negative case isn't a shared cross-backend assertion — see IkeDeriveTestCases's doc comment.
    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void IkePrf_RejectsGenericSecretBaseKey() => IkeDeriveTestCases.Assert_IkePrf_RejectsGenericSecretBaseKey(_backend);
}
