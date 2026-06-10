using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>Cross-backend port of the SoftHSM2 key wrap/unwrap integration tests, run against opencryptoki.</summary>
[Collection("OpenCryptoki")]
public sealed class WrapUnwrapKeyTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    [ConditionalFact(nameof(Available))]
    public void AesKeyWrapPad_RoundTrip() => WrapUnwrapKeyTestCases.Assert_AesKeyWrapPad_RoundTrip(_backend);

    [ConditionalFact(nameof(Available))]
    public void Unwrap_AppliesSecureDefaults() => WrapUnwrapKeyTestCases.Assert_Unwrap_AppliesSecureDefaults(_backend);

    [ConditionalFact(nameof(Available))]
    public void Unwrap_ExplicitExtractable_RequiresAllowInsecure() => WrapUnwrapKeyTestCases.Assert_Unwrap_ExplicitExtractable_RequiresAllowInsecure(_backend);
}
