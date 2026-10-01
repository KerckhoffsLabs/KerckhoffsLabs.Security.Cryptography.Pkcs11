using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>Marshalling round trips for the AEAD message-based params (CK_*_MESSAGE_PARAMS).</summary>
public sealed class MechanismAeadMessageParamsTests
{
    [Fact]
    public void GcmMessage_ForEncrypt_MarshalsIvAndTagBits()
    {
        byte[] iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        var p = CkmGcmMessageParams.ForEncrypt(iv, tagBytes: 16);
        using var scope = new MechanismParameterScope();
        var s = ParamMarshal.RoundTrip<CK_GCM_MESSAGE_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal((ulong)iv.Length, (ulong)s.IvLen);
        Assert.Equal(iv, UnmanagedMemory.Read(s.Iv, iv.Length));
        Assert.Equal(128UL, (ulong)s.TagBits); // 16 bytes
        Assert.NotEqual(IntPtr.Zero, s.Tag);    // pre-allocated output buffer
    }

    [Fact]
    public void GcmMessage_ForDecrypt_CopiesCallerTagBytes()
    {
        byte[] iv = [9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9];
        byte[] tag = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        var p = CkmGcmMessageParams.ForDecrypt(iv, tag);
        using var scope = new MechanismParameterScope();
        var s = ParamMarshal.RoundTrip<CK_GCM_MESSAGE_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal(tag, UnmanagedMemory.Read(s.Tag, tag.Length));
    }

    [Theory]
    [InlineData(3)]
    [InlineData(17)]
    public void GcmMessage_RejectsBadTagLen(int tagBytes) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes));

    [Fact]
    public void GcmMessage_RejectsEmptyIv() =>
        Assert.Throws<ArgumentException>(() => CkmGcmMessageParams.ForEncrypt(default, 16));

    [Fact]
    public void CcmMessage_ForEncrypt_MarshalsNonceDataAndMacLen()
    {
        byte[] nonce = [1, 2, 3, 4, 5, 6, 7]; // 7..13
        var p = CkmCcmMessageParams.ForEncrypt(dataLen: 64, nonce, macBytes: 16);
        using var scope = new MechanismParameterScope();
        var s = ParamMarshal.RoundTrip<CK_CCM_MESSAGE_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal(64UL, (ulong)s.DataLen);
        Assert.Equal((ulong)nonce.Length, (ulong)s.NonceLen);
        Assert.Equal(nonce, UnmanagedMemory.Read(s.Nonce, nonce.Length));
        Assert.Equal(16UL, (ulong)s.MacLen);
        Assert.NotEqual(IntPtr.Zero, s.Mac);
    }

    [Fact]
    public void CcmMessage_ForDecrypt_CopiesCallerMacBytes()
    {
        byte[] nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        byte[] mac = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];
        var p = CkmCcmMessageParams.ForDecrypt(dataLen: 32, nonce, mac);
        using var scope = new MechanismParameterScope();
        var s = ParamMarshal.RoundTrip<CK_CCM_MESSAGE_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal((ulong)mac.Length, (ulong)s.MacLen);
        Assert.Equal(mac, UnmanagedMemory.Read(s.Mac, mac.Length));
    }

    [Theory]
    [InlineData(6)]  // below 7
    [InlineData(14)] // above 13
    public void CcmMessage_RejectsBadNonceLength(int nonceLen) =>
        Assert.Throws<ArgumentException>(() => CkmCcmMessageParams.ForEncrypt(32, new byte[nonceLen], 16));

    [Theory]
    [InlineData(13, 65_535)]
    [InlineData(12, 16_777_215)]
    [InlineData(11, int.MaxValue)]
    [InlineData(7, int.MaxValue)]
    public void CcmMessage_AcceptsDataLenThatFitsTheLengthField(int nonceLen, int dataLen)
    {
        var p = CkmCcmMessageParams.ForEncrypt(dataLen, new byte[nonceLen], macBytes: 16);
        using var scope = new MechanismParameterScope();
        var s = ParamMarshal.RoundTrip<CK_CCM_MESSAGE_PARAMS>(p.BuildMarshalable(scope));
        Assert.Equal((ulong)dataLen, (ulong)s.DataLen);
    }

    [Theory]
    [InlineData(13, 65_536)]       // 2-byte length field
    [InlineData(12, 16_777_216)]   // 3-byte length field
    public void CcmMessage_RejectsDataLenBeyondTheLengthField(int nonceLen, int dataLen)
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(
            () => CkmCcmMessageParams.ForDecrypt(dataLen, new byte[nonceLen], new byte[16]));
        Assert.Equal("dataLen", ex.ParamName);
    }

    [Theory]
    [InlineData(5)]
    [InlineData(18)]
    public void CcmMessage_RejectsBadMacLen(int macBytes) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => CkmCcmMessageParams.ForEncrypt(32, new byte[8], macBytes));

    [Fact]
    public void SalsaChaChaPoly1305Message_ForEncrypt_MarshalsNonce()
    {
        byte[] nonce = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        var p = CkmSalsa20ChaCha20Poly1305MsgParams.ForEncrypt(nonce);
        using var scope = new MechanismParameterScope();
        var s = ParamMarshal.RoundTrip<CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal((ulong)nonce.Length, (ulong)s.NonceLen);
        Assert.Equal(nonce, UnmanagedMemory.Read(s.Nonce, nonce.Length));
        Assert.NotEqual(IntPtr.Zero, s.Tag);
    }

    [Fact]
    public void SalsaChaChaPoly1305Message_ForDecrypt_CopiesTag()
    {
        byte[] nonce = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        byte[] tag = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        var p = CkmSalsa20ChaCha20Poly1305MsgParams.ForDecrypt(nonce, tag);
        using var scope = new MechanismParameterScope();
        var s = ParamMarshal.RoundTrip<CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal(tag, UnmanagedMemory.Read(s.Tag, tag.Length));
    }

    [Fact]
    public void SalsaChaChaPoly1305Message_ForDecrypt_RejectsNon16ByteTag() =>
        Assert.Throws<ArgumentException>(() => CkmSalsa20ChaCha20Poly1305MsgParams.ForDecrypt(new byte[12], new byte[15]));
}
