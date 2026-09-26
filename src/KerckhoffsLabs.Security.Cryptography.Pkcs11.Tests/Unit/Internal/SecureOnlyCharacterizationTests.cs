using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

#pragma warning disable KLPKCS11008, KLPKCS11009 // the gated mechanisms are the subject under test

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// Pins the default gate's behaviour that the whole-enum parity test cannot see: verdicts that depend
/// on mechanism parameters, the pass-through of mechanisms the gate has never heard of, and the fact
/// that the verdict does not depend on the operation's direction. The policy refactor must keep all
/// three exactly as they are.
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

    [Fact]
    public void Oaep_WithoutParameters_IsNotRefusedByTheGate()
    {
        using var session = NewSession();
        Exception? ex = Record.Exception(() => session.Encrypt(new Mechanism(CKM.CKM_RSA_PKCS_OAEP), AnyKey, [1]));
        Assert.False(ex is CryptoPolicyViolationException, $"Gate refused parameterless OAEP: {ex}");
    }

    [Fact]
    public void VendorDefinedMechanism_IsNotRefusedByTheGate()
    {
        using var session = NewSession();
        Exception? ex = Record.Exception(() => session.Encrypt(new Mechanism(0x8000_1234UL), AnyKey, [1]));
        Assert.False(ex is CryptoPolicyViolationException, $"Gate refused a vendor mechanism: {ex}");
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
