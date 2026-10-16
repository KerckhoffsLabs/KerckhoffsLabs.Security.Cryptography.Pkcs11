using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Derive;

/// <summary>The IKE-derive family over Craton HSM — thin wrapper over <see cref="IkeDeriveTestCases"/>.</summary>
[Collection("CratonHsm")]
[ResetCratonHsmLogin]
public sealed class IkeDeriveTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void IkePrf_MatchesReference() => IkeDeriveTestCases.Assert_IkePrf_MatchesReference(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Ike1Prf_MatchesReference() => IkeDeriveTestCases.Assert_Ike1Prf_MatchesReference(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Ike1ExtendedDerive_MatchesReference() => IkeDeriveTestCases.Assert_Ike1ExtendedDerive_MatchesReference(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Ike2PrfPlusDerive_MatchesReference() => IkeDeriveTestCases.Assert_Ike2PrfPlusDerive_MatchesReference(_backend);

    // Sign-probe variants: same derivations, verified without reading CKA_VALUE — see
    // IkeDeriveTestCases's class doc comment for why this is a useful cross-check on its own.

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void IkePrf_MatchesBclViaSignProbe() => IkeDeriveTestCases.Assert_IkePrf_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Ike1Prf_MatchesBclViaSignProbe() => IkeDeriveTestCases.Assert_Ike1Prf_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Ike1ExtendedDerive_MatchesBclViaSignProbe() => IkeDeriveTestCases.Assert_Ike1ExtendedDerive_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Ike2PrfPlusDerive_MatchesBclViaSignProbe() => IkeDeriveTestCases.Assert_Ike2PrfPlusDerive_MatchesBclViaSignProbe(_backend);

    // Craton HSM-only: NSS's sftkike.c never checks the base key's CKA_KEY_TYPE at all, so this
    // negative case isn't a shared cross-backend assertion — see IkeDeriveTestCases's doc comment.
    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void IkePrf_RejectsGenericSecretBaseKey() => IkeDeriveTestCases.Assert_IkePrf_RejectsGenericSecretBaseKey(_backend);
}
