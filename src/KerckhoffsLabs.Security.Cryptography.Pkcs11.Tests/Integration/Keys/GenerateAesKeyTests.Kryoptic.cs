using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

[Collection("Kryoptic")]
public sealed class GenerateAesKeyTests_Kryoptic(KryopticBackendFixture f)
{
    private readonly KryopticBackendFixture _backend = f;
    public static bool KryopticAvailable => KryopticBackendFixture.KryopticAvailable;

    [ConditionalFact(nameof(KryopticAvailable))]
    public void RejectsWrongBitLength() => GenerateAesKeyTestCases.Assert_RejectsWrongBitLength(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void GeneratesAes256Key() => GenerateAesKeyTestCases.Assert_GeneratesAes256Key(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void GeneratedKey_HasNoWrapCapability() => GenerateAesKeyTestCases.Assert_GeneratedKey_HasNoWrapCapability(_backend);

    // Kryoptic denies CKA_WRAP_TEMPLATE/CKA_UNWRAP_TEMPLATE outright at template-validation time
    // (CKR_ATTRIBUTE_TYPE_INVALID) -- it doesn't just mishandle them, there's no equivalent call that
    // would succeed. Upstream is already tracking this as a real feature, not a bug: issue
    // https://github.com/latchset/kryoptic/issues/434 ("Implement template attributes"), with an open
    // PR implementing it at https://github.com/latchset/kryoptic/pull/500. Flip this back on (and drop
    // the comment) once that lands and a submodule bump picks it up.
    public static bool SupportsWrapUnwrapTemplate => false;

    [ConditionalFact(nameof(SupportsWrapUnwrapTemplate))]
    public void GeneratesKeyEncryptionKey_WrapUnwrapOnly() => GenerateAesKeyTestCases.Assert_GeneratesKeyEncryptionKey_WrapUnwrapOnly(_backend);
}
