using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

[Collection("WolfPkcs11")]
public sealed class GenerateAesKeyTests_WolfPkcs11(WolfPkcs11BackendFixture f)
{
    private readonly WolfPkcs11BackendFixture _backend = f;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void RejectsWrongBitLength() => GenerateAesKeyTestCases.Assert_RejectsWrongBitLength(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void GeneratesAes256Key() => GenerateAesKeyTestCases.Assert_GeneratesAes256Key(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void GeneratedKey_HasNoWrapCapability() => GenerateAesKeyTestCases.Assert_GeneratedKey_HasNoWrapCapability(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WrapTemplateAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 refuses CKA_WRAP_TEMPLATE and CKA_UNWRAP_TEMPLATE in C_GenerateKey")]
    public void GeneratesKeyEncryptionKey_WrapUnwrapOnly() => GenerateAesKeyTestCases.Assert_GeneratesKeyEncryptionKey_WrapUnwrapOnly(_backend);
}
