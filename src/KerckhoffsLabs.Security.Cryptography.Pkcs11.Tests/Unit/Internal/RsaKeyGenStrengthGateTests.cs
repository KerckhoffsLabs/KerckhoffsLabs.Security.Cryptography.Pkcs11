using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// RSA key sizes below the NIST SP 800-131A 2048-bit floor are gated behind the session's crypto
/// policy — generating a sub-2048 RSA key pair must throw <see cref="CryptoPolicyViolationException"/>
/// unless the policy permits it, mirroring the mechanism-level secure-defaults gate.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class RsaKeyGenStrengthGateTests
{
    private sealed class RecordingFake : SessionTestModule
    {
        public new int Calls { get; private set; }

        protected override CKR C_GenerateKeyPair(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] publicKeyTemplate, CK_ATTRIBUTE[] privateKeyTemplate, ref NativeCULong publicKey, ref NativeCULong privateKey)
        {
            Calls++;
            publicKey = (NativeCULong)10UL;
            privateKey = (NativeCULong)11UL;
            return CKR.CKR_OK;
        }
    }

    private static void GenerateRsa(Pkcs11Session session, int modulusBits)
    {
        var mech = new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .ModulusBits(modulusBits).PublicExponent([0x01, 0x00, 0x01]).Verify().Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA).Sign().Build();
        session.GenerateKeyPair(mech, [.. pubTpl.Attributes], [.. privTpl.Attributes], out _, out _);
    }

    [Fact]
    public void GenerateKeyPair_Rsa1024_GatedByDefault_Throws()
    {
        using var fake = new RecordingFake();
        using var session = fake.CreateSession(sessionId: 1);
        Assert.Throws<CryptoPolicyViolationException>(() => GenerateRsa(session, 1024));
        Assert.Equal(0, fake.Calls); // refused before reaching the token
    }

    [Fact]
    public void GenerateKeyPair_Rsa1024_AllowInsecure_Proceeds()
    {
        using var fake = new RecordingFake();
        using var session = fake.CreateSession(sessionId: 1, policy: CryptoPolicy.AllowInsecure);
        GenerateRsa(session, 1024);
        Assert.Equal(1, fake.Calls);
    }

    [Fact]
    public void GenerateKeyPair_Rsa2048_Proceeds_WithoutAllowInsecure()
    {
        using var fake = new RecordingFake();
        using var session = fake.CreateSession(sessionId: 1);
        GenerateRsa(session, 2048);
        Assert.Equal(1, fake.Calls);
    }
}
