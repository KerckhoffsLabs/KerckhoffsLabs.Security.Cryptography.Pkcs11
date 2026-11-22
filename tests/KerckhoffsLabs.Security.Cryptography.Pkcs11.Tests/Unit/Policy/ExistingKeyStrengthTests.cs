using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

#pragma warning disable KLPKCS11007 // weak curves are the subject under test

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

/// <summary>
/// <c>Recommended</c> and <c>NistApproved</c> judge an existing RSA or EC key by its modulus or curve each time it is
/// used. <c>NistApproved</c> keeps SP 800-131A Rev.2 Table 2's one legacy use, verifying an old signature; Recommended
/// keeps none.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class ExistingKeyStrengthTests
{
    private static KeyStrengthRequest Rsa(int? bits, CryptoOperation? operation) =>
        new(CKK.CKK_RSA, KeyStrengthSource.ExistingKey) { ModulusBits = bits, Operation = operation };

    private static KeyStrengthRequest Ec(Pkcs11ECCurve? curve, CryptoOperation? operation) =>
        new(CKK.CKK_EC, KeyStrengthSource.ExistingKey) { Curve = curve, Operation = operation };

    public static TheoryData<int, CryptoOperation, bool, bool> RsaCases() => new()
    {
        // bits, operation, Recommended allows, NistApproved allows
        { 4096, CryptoOperation.Sign, true, true },
        { 2048, CryptoOperation.Decrypt, true, true },
        { 2048, CryptoOperation.Verify, true, true },
        { 2047, CryptoOperation.Verify, false, true },
        { 1024, CryptoOperation.Verify, false, true },
        { 1023, CryptoOperation.Verify, false, false },
        { 1024, CryptoOperation.Sign, false, false },
        { 1024, CryptoOperation.Decrypt, false, false },
        { 1024, CryptoOperation.Unwrap, false, false },
        { 1024, CryptoOperation.Encrypt, false, false },
    };

    [Theory]
    [MemberData(nameof(RsaCases))]
    public void Rsa_IsJudgedByItsModulus_AndNistApprovedLetsAnOldKeyVerify(int bits, CryptoOperation operation, bool recommended, bool nist)
    {
        Assert.Equal(recommended, CryptoPolicy.Recommended.Evaluate(Rsa(bits, operation)).IsAllowed);
        Assert.Equal(nist, CryptoPolicy.NistApproved.Evaluate(Rsa(bits, operation)).IsAllowed);
    }

    public static TheoryData<string, CryptoOperation, bool, bool> CurveCases() => new()
    {
        // curve, operation, Recommended allows, NistApproved allows
        { "NistP256", CryptoOperation.Sign, true, true },
        { "NistP384", CryptoOperation.Derive, true, true },
        { "NistP224", CryptoOperation.Sign, false, true },   // below Recommended's 128-bit baseline; approved by SP 800-186
        { "NistP192", CryptoOperation.Verify, false, true },  // SP 800-131A Rev.2 Table 2: 160 <= len(n) < 224, legacy use
        { "NistP192", CryptoOperation.Sign, false, false },
        { "NistP192", CryptoOperation.Derive, false, false }, // Table 4: ECDH below 224 bits is disallowed
    };

    [Theory]
    [MemberData(nameof(CurveCases))]
    public void Ec_IsJudgedByItsCurve_AndNistApprovedLetsAnOldKeyVerify(string curve, CryptoOperation operation, bool recommended, bool nist)
    {
        Pkcs11ECCurve named = curve switch
        {
            "NistP256" => Pkcs11ECCurve.NamedCurves.NistP256,
            "NistP384" => Pkcs11ECCurve.NamedCurves.NistP384,
            "NistP224" => Pkcs11ECCurve.NamedCurves.NistP224,
            _ => Pkcs11ECCurve.NamedCurves.NistP192,
        };
        Assert.Equal(recommended, CryptoPolicy.Recommended.Evaluate(Ec(named, operation)).IsAllowed);
        Assert.Equal(nist, CryptoPolicy.NistApproved.Evaluate(Ec(named, operation)).IsAllowed);
    }

    // The modulus and the curve are public on every key: one the token does not report can't be checked, and is refused.
    [Theory]
    [InlineData("Recommended")]
    [InlineData("NistApproved")]
    public void AnUnreportedModulusOrCurve_IsRefused(string name)
    {
        ComposedCryptoPolicy policy = name == "Recommended" ? CryptoPolicy.Recommended : CryptoPolicy.NistApproved;

        Assert.Contains("CKA_MODULUS", policy.Evaluate(Rsa(null, CryptoOperation.Verify)).Reason, StringComparison.Ordinal);
        Assert.Contains("named curve", policy.Evaluate(Ec(null, CryptoOperation.Verify)).Reason, StringComparison.Ordinal);
    }

    // C_SetOperationState restores an operation the library can't name: no legacy use applies.
    [Fact]
    public void AUseThatIsNotOneOperation_GetsNoLegacyUse()
        => Assert.False(CryptoPolicy.NistApproved.Evaluate(Rsa(1024, operation: null)).IsAllowed);

    [Fact]
    public void TheRefusal_NamesTheSizeAndTheOperation()
    {
        PolicyDecision decision = CryptoPolicy.Recommended.Evaluate(Rsa(1024, CryptoOperation.Sign));

        Assert.Contains("1024 bits", decision.Reason, StringComparison.Ordinal);
        Assert.Contains("Sign", decision.Reason, StringComparison.Ordinal);
    }

    // End to end over the managed soft token: the modulus is read from the token on each use, and judged.
    [Fact]
    public void AnRsa1024KeyOnTheToken_CannotSignUnderRecommended_AndOnlyVerifiesUnderNistApproved()
    {
        using var library = ManagedToken.NewLibrary(CryptoPolicy.AllowInsecure);
        using var session = ManagedToken.OpenSession(library);
        using Pkcs11Key key = session.GenerateRsaSigningKeyPair(modulusBits: 1024);
        var pss = new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32));
        byte[] data = [1, 2, 3];
        byte[] signature = key.Sign(pss, data);

        using (session.UsePolicy(CryptoPolicy.Recommended))
        {
            var refused = Assert.Throws<CryptoPolicyViolationException>(() => key.Sign(pss, data));
            var request = Assert.IsType<KeyStrengthRequest>(refused.Request);
            Assert.Equal(1024, request.ModulusBits);
            Assert.Equal(CryptoOperation.Sign, request.Operation);
            Assert.Contains("of 1024 bits (existing key, for Sign)", refused.Message, StringComparison.Ordinal);
            Assert.Throws<CryptoPolicyViolationException>(() => key.Verify(pss, data, signature));
        }

        using (session.UsePolicy(CryptoPolicy.NistApproved))
        {
            Assert.True(key.Verify(pss, data, signature));
            Assert.Throws<CryptoPolicyViolationException>(() => key.Sign(pss, data));
        }
    }

    [Fact]
    public void Rsa2048AndP256KeysOnTheToken_AreUsedUnderRecommended()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using Pkcs11Key rsa = session.GenerateRsaSigningKeyPair(modulusBits: 2048);
        using Pkcs11Key ec = session.GenerateEcSigningKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        var pss = new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32));
        var ecdsa = new Mechanism(CKM.CKM_ECDSA_SHA256);
        byte[] data = [1, 2, 3];

        Assert.True(rsa.Verify(pss, data, rsa.Sign(pss, data)));
        Assert.True(ec.Verify(ecdsa, data, ec.Sign(ecdsa, data)));
    }
}
