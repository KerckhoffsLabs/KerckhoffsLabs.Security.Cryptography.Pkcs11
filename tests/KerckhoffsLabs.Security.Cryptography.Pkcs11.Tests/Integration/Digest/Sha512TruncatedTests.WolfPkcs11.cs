using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Digest;

/// <summary>SHA-512/224 and SHA-512/256 over wolfPKCS11 — thin wrapper over <see cref="Sha512TruncatedTestCases"/>.</summary>
[Collection("WolfPkcs11")]
public sealed class Sha512TruncatedTests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Sha512_224_Kat() =>
        Sha512TruncatedTestCases.Assert_Sha512_224_Kat(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Sha512_256_Kat() =>
        Sha512TruncatedTestCases.Assert_Sha512_256_Kat(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void HmacSha512_224_Kat() =>
        Sha512TruncatedTestCases.Assert_HmacSha512_224_Kat(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void HmacSha512_256_Kat() =>
        Sha512TruncatedTestCases.Assert_HmacSha512_256_Kat(_backend);
}
