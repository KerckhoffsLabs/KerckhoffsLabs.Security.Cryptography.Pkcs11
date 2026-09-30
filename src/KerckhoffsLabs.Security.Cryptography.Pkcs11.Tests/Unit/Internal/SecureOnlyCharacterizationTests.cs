using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

#pragma warning disable KLPKCS11008, KLPKCS11009 // the gated mechanisms are the subject under test

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// Pins the default policy's behaviour at the session boundary that the whole-enum tests cannot see:
/// verdicts that depend on mechanism parameters, the denial of mechanisms the policy has never reviewed
/// (vendor-defined ones included), and denials that hold in both directions of an operation pair.
/// </summary>
public sealed class SecureOnlyCharacterizationTests
{
    private static readonly ObjectHandle AnyKey = new(0);

    private static Pkcs11Session NewSession() => new(new FakeLowLevelPkcs11Library(), sessionId: 1);

    private static Mechanism Oaep(CKM hash, CKG mgf) => new(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(hash, mgf));

    [Theory]
    [InlineData(CKM.CKM_SHA_1, CKG.CKG_MGF1_SHA1)]
    [InlineData(CKM.CKM_SHA224, CKG.CKG_MGF1_SHA224)]
    public void Oaep_WithWeakHash_IsRefused(CKM hash, CKG mgf)
    {
        using var session = NewSession();
        Assert.Throws<CryptoPolicyViolationException>(() => session.Encrypt(Oaep(hash, mgf), AnyKey, [1]));
    }

    [Fact]
    public void Oaep_WithSha256_IsNotRefusedByTheGate()
    {
        using var session = NewSession();
        Exception? ex = Record.Exception(() => session.Encrypt(Oaep(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256), AnyKey, [1]));
        Assert.False(ex is CryptoPolicyViolationException, $"Gate refused OAEP-SHA256: {ex}");
    }

    // Without CkmRsaPkcsOaepParams the token picks the OAEP hash (typically SHA-1), so the policy cannot
    // vouch for it.
    [Fact]
    public void Oaep_WithoutParameters_IsDenied()
    {
        using var session = NewSession();
        Assert.Throws<CryptoPolicyViolationException>(() => session.Encrypt(new Mechanism(CKM.CKM_RSA_PKCS_OAEP), AnyKey, [1]));
    }

    [Fact]
    public void VendorDefinedMechanism_IsDenied()
    {
        using var session = NewSession();
        var ex = Assert.Throws<CryptoPolicyViolationException>(() => session.Encrypt(new Mechanism((CKM)0x8000_1234UL), AnyKey, [1]));
        Assert.Contains("not on the SecureOnly allow-list", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Verdict_IsDirectionAgnostic_ForSha1RsaSignatures()
    {
        using var session = NewSession();
        var mech = new Mechanism(CKM.CKM_SHA1_RSA_PKCS);
        Assert.Throws<CryptoPolicyViolationException>(() => session.Sign(mech, AnyKey, [1]));
        Assert.Throws<CryptoPolicyViolationException>(() => session.Verify(mech, AnyKey, [1], [1], out _));
    }

    [Fact]
    public void Verdict_IsDirectionAgnostic_ForRsaPkcs1v15Encryption()
    {
        using var session = NewSession();
        var mech = new Mechanism(CKM.CKM_RSA_PKCS);
        Assert.Throws<CryptoPolicyViolationException>(() => session.Encrypt(mech, AnyKey, [1]));
        Assert.Throws<CryptoPolicyViolationException>(() => session.Decrypt(mech, AnyKey, [1]));
    }
}
