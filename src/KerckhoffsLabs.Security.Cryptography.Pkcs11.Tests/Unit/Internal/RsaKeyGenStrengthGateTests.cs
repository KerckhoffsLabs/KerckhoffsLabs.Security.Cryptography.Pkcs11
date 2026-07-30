using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// RSA key sizes below the NIST SP 800-131A 2048-bit floor are gated behind AllowInsecure at the
/// session layer — generating a sub-2048 RSA key pair must throw <see cref="InsecureOperationException"/>
/// unless the workspace opts in, mirroring the mechanism-level secure-defaults gate.
/// </summary>
public sealed class RsaKeyGenStrengthGateTests
{
    private sealed class RecordingFake : FakeLowLevelPkcs11Library
    {
        public int Calls { get; private set; }

        public override CKR C_GenerateKeyPair(
            NativeCULong session, ref CK_MECHANISM mechanism,
            CK_ATTRIBUTE[]? publicKeyTemplate, NativeCULong publicKeyAttributeCount,
            CK_ATTRIBUTE[]? privateKeyTemplate, NativeCULong privateKeyAttributeCount,
            ref NativeCULong publicKey, ref NativeCULong privateKey)
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
        var fake = new RecordingFake();
        var session = new Pkcs11Session(fake, sessionId: 1);
        try
        {
            Assert.Throws<InsecureOperationException>(() => GenerateRsa(session, 1024));
            Assert.Equal(0, fake.Calls); // refused before reaching the token
        }
        finally { session.CloseSession(); }
    }

    [Fact]
    public void GenerateKeyPair_Rsa1024_AllowInsecure_Proceeds()
    {
        var fake = new RecordingFake();
        var session = new Pkcs11Session(fake, sessionId: 1) { AllowInsecure = true };
        try
        {
            GenerateRsa(session, 1024);
            Assert.Equal(1, fake.Calls);
        }
        finally { session.CloseSession(); }
    }

    [Fact]
    public void GenerateKeyPair_Rsa2048_Proceeds_WithoutAllowInsecure()
    {
        var fake = new RecordingFake();
        var session = new Pkcs11Session(fake, sessionId: 1);
        try
        {
            GenerateRsa(session, 2048);
            Assert.Equal(1, fake.Calls);
        }
        finally { session.CloseSession(); }
    }
}
