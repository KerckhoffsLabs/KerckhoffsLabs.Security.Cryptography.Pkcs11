using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>Marshalling round trips for the Signal-protocol params (X3DH / Double Ratchet).</summary>
public sealed class MechanismSignalParamsTests
{
    [Fact]
    public void X3dhInitiate_MarshalsHandlesAndKeyBytes()
    {
        byte[] sig = [1, 2, 3];
        byte[] otk = [4, 5];
        using var keys = new ParameterKeys();
        var p = new CkmX3dhInitiateParams(kdf: CKM.CKM_SHA256_HMAC, peerIdentity: keys.PublicOnly(2), peerPrekey: keys.PublicOnly(3), sig, otk,
            ownIdentity: keys.Pair(4, 0x40), ownEphemeral: keys.Pair(5, 0x50));
        using var scope = keys.NewScope();
        var s = ParamMarshal.RoundTrip<CK_X3DH_INITIATE_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal((ulong)CKM.CKM_SHA256_HMAC, (ulong)s.Kdf);
        Assert.Equal(2UL, (ulong)s.PeerIdentity);
        Assert.Equal(3UL, (ulong)s.PeerPrekey);
        Assert.Equal(4UL, (ulong)s.OwnIdentity);
        Assert.Equal(5UL, (ulong)s.OwnEphemeral);
        Assert.Equal(sig, UnmanagedMemory.Read(s.PrekeySignature, sig.Length));
        Assert.Equal(otk, UnmanagedMemory.Read(s.OnetimeKey, otk.Length));
    }

    [Fact]
    public void X3dhRespond_MarshalsHandlesAndIdBytes()
    {
        byte[] id = [0x11];
        byte[] pre = [0x22, 0x23];
        byte[] otp = [0x33];
        byte[] eph = [0x44, 0x45, 0x46];
        using var keys = new ParameterKeys();
        var p = new CkmX3dhRespondParams(kdf: CKM.CKM_SHA384_HMAC, id, pre, otp, initiatorIdentity: keys.PublicOnly(8), eph);
        using var scope = keys.NewScope();
        var s = ParamMarshal.RoundTrip<CK_X3DH_RESPOND_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal((ulong)CKM.CKM_SHA384_HMAC, (ulong)s.Kdf);
        Assert.Equal(8UL, (ulong)s.InitiatorIdentity);
        Assert.Equal(id, UnmanagedMemory.Read(s.IdentityId, id.Length));
        Assert.Equal(pre, UnmanagedMemory.Read(s.PrekeyId, pre.Length));
        Assert.Equal(otp, UnmanagedMemory.Read(s.OnetimeId, otp.Length));
        Assert.Equal(eph, UnmanagedMemory.Read(s.InitiatorEphemeral, eph.Length));
    }

    [Fact]
    public void X2RatchetInitialize_MarshalsSecretFlagsAndMechanisms()
    {
        byte[] sk = [1, 2, 3, 4, 5, 6, 7, 8];
        using var keys = new ParameterKeys();
        var p = new CkmX2RatchetInitializeParams(sk, peerPublicPrekey: keys.PublicOnly(1), peerPublicIdentity: keys.PublicOnly(2),
            ownPublicIdentity: keys.Pair(0x30, 3), encryptedHeader: true, curve: 4, CKM.CKM_AES_GCM, kdfMechanism: CKM.CKM_SHA256_HMAC);
        using var scope = keys.NewScope();
        var s = ParamMarshal.RoundTrip<CK_X2RATCHET_INITIALIZE_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal(sk, UnmanagedMemory.Read(s.Sk, sk.Length));
        Assert.Equal(1UL, (ulong)s.PeerPublicPrekey);
        Assert.Equal(2UL, (ulong)s.PeerPublicIdentity);
        Assert.Equal(3UL, (ulong)s.OwnPublicIdentity);
        Assert.Equal(CkBbool.True, s.EncryptedHeader);
        Assert.Equal(4UL, (ulong)s.Curve);
        Assert.Equal((ulong)CKM.CKM_AES_GCM, (ulong)s.AeadMechanism);
        Assert.Equal((ulong)CKM.CKM_SHA256_HMAC, (ulong)s.KdfMechanism);
    }

    [Fact]
    public void X2RatchetInitialize_RejectsEmptySharedSecret()
    {
        using var keys = new ParameterKeys();
        var e = Assert.Throws<ArgumentException>(() => new CkmX2RatchetInitializeParams(
            default, keys.PublicOnly(1), keys.PublicOnly(2), keys.Pair(0x30, 3), false, 4, CKM.CKM_AES_GCM, CKM.CKM_SHA256_HMAC));
        Assert.Equal("sk", e.ParamName);
    }

    [Fact]
    public void X2RatchetRespond_MarshalsSecretFlagsAndMechanisms()
    {
        byte[] sk = [9, 8, 7, 6];
        using var keys = new ParameterKeys();
        var p = new CkmX2RatchetRespondParams(sk, ownPrekey: keys.Pair(1, 0x10), initiatorIdentity: keys.PublicOnly(2),
            ownPublicIdentity: keys.Pair(0x30, 3), encryptedHeader: false, curve: 4, CKM.CKM_AES_GCM, kdfMechanism: CKM.CKM_SHA384_HMAC);
        using var scope = keys.NewScope();
        var s = ParamMarshal.RoundTrip<CK_X2RATCHET_RESPOND_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal(sk, UnmanagedMemory.Read(s.Sk, sk.Length));
        Assert.Equal(1UL, (ulong)s.OwnPrekey);
        Assert.Equal(2UL, (ulong)s.InitiatorIdentity);
        Assert.Equal(3UL, (ulong)s.OwnPublicIdentity);
        Assert.Equal(CkBbool.False, s.EncryptedHeader);
        Assert.Equal(4UL, (ulong)s.Curve);
        Assert.Equal((ulong)CKM.CKM_AES_GCM, (ulong)s.AeadMechanism);
        Assert.Equal((ulong)CKM.CKM_SHA384_HMAC, (ulong)s.KdfMechanism);
    }

    [Fact]
    public void X2RatchetRespond_RejectsEmptySharedSecret()
    {
        using var keys = new ParameterKeys();
        var e = Assert.Throws<ArgumentException>(() => new CkmX2RatchetRespondParams(
            default, keys.Pair(1, 0x10), keys.PublicOnly(2), keys.Pair(0x30, 3), false, 4, CKM.CKM_AES_GCM, CKM.CKM_SHA384_HMAC));
        Assert.Equal("sk", e.ParamName);
    }
}
