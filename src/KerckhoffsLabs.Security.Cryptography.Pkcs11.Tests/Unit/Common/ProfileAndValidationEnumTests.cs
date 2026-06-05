// Licensed under the MIT License

using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Common;

/// <summary>
/// Pins the underlying values of the PKCS#11 v3.2 validation-flags-type and profile-ID enums to
/// the spec constants (<c>CK_SESSION_VALIDATION_FLAGS_TYPE</c> / <c>CK_PROFILE_ID</c>). These are
/// wire values passed to / read from the token, so a wrong number is silently interoperability-breaking.
/// </summary>
public sealed class ProfileAndValidationEnumTests
{
    [Fact]
    public void CksValidationFlagsType_HasSpecValue()
        => Assert.Equal(1u, (uint)CksValidationFlagsType.CKS_LAST_VALIDATION_OK);

    [Theory]
    [InlineData(CkpProfile.CKP_INVALID_ID, 0u)]
    [InlineData(CkpProfile.CKP_BASELINE_PROVIDER, 1u)]
    [InlineData(CkpProfile.CKP_EXTENDED_PROVIDER, 2u)]
    [InlineData(CkpProfile.CKP_AUTHENTICATION_TOKEN, 3u)]
    [InlineData(CkpProfile.CKP_PUBLIC_CERTIFICATES_TOKEN, 4u)]
    [InlineData(CkpProfile.CKP_COMPLETE_PROVIDER, 5u)]
    [InlineData(CkpProfile.CKP_HKDF_TLS_TOKEN, 6u)]
    public void CkpProfile_HasSpecValue(CkpProfile profile, uint expected)
        => Assert.Equal(expected, (uint)profile);
}
