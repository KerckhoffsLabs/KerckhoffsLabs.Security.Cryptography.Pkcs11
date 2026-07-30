using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.MechanismParams;

/// <summary>
/// Covers the tag/MAC read-back methods on the v3.0 message-based AEAD param wrappers
/// (<c>CopyTagTo</c> / <c>CopyMacTo</c>) — the post-encrypt path the marshal tests don't exercise:
/// the happy copy and the too-small-destination guard.
/// </summary>
public sealed class MessageParamsCopyTagTests
{
    [Fact]
    public void GcmMessage_CopyTagTo_FillsDestination()
    {
        using var p = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);
        byte[] tag = new byte[16];
        Assert.Null(Record.Exception(() => p.CopyTagTo(tag))); // tag buffer is allocated; readable
    }

    [Fact]
    public void GcmMessage_CopyTagTo_TooSmall_Throws()
    {
        using var p = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);
        Assert.Throws<ArgumentException>(() => p.CopyTagTo(new byte[15]));
    }

    [Fact]
    public void GcmMessage_CopyTagTo_AfterDispose_Throws()
    {
        var p = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);
        p.Dispose();
        Assert.Throws<ObjectDisposedException>(() => p.CopyTagTo(new byte[16]));
    }

    [Fact]
    public void GcmMessage_ForDecrypt_RoundTripsCallerTag()
    {
        byte[] tag = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        using var p = CkmGcmMessageParams.ForDecrypt(new byte[12], tag);
        byte[] readBack = new byte[16];
        p.CopyTagTo(readBack);
        Assert.Equal(tag, readBack);
    }

    [Fact]
    public void CcmMessage_CopyMacTo_FillsDestination()
    {
        using var p = CkmCcmMessageParams.ForEncrypt(dataLen: 64, new byte[13], macBytes: 16);
        Assert.Null(Record.Exception(() => p.CopyMacTo(new byte[16])));
    }

    [Fact]
    public void CcmMessage_CopyMacTo_TooSmall_Throws()
    {
        using var p = CkmCcmMessageParams.ForEncrypt(dataLen: 64, new byte[13], macBytes: 16);
        Assert.Throws<ArgumentException>(() => p.CopyMacTo(new byte[15]));
    }

    [Fact]
    public void CcmMessage_ForDecrypt_RoundTripsCallerMac()
    {
        byte[] mac = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        using var p = CkmCcmMessageParams.ForDecrypt(dataLen: 32, new byte[13], mac);
        byte[] readBack = new byte[16];
        p.CopyMacTo(readBack);
        Assert.Equal(mac, readBack);
    }

    [Fact]
    public void SalsaChaChaPoly1305Message_CopyTagTo_FillsDestination()
    {
        using var p = CkmSalsa20ChaCha20Poly1305MsgParams.ForEncrypt(new byte[12]);
        Assert.Null(Record.Exception(() => p.CopyTagTo(new byte[16])));
    }

    [Fact]
    public void SalsaChaChaPoly1305Message_CopyTagTo_TooSmall_Throws()
    {
        using var p = CkmSalsa20ChaCha20Poly1305MsgParams.ForEncrypt(new byte[12]);
        Assert.Throws<ArgumentException>(() => p.CopyTagTo(new byte[15]));
    }

    [Fact]
    public void SalsaChaChaPoly1305Message_ForDecrypt_RoundTripsCallerTag()
    {
        byte[] tag = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        using var p = CkmSalsa20ChaCha20Poly1305MsgParams.ForDecrypt(new byte[12], tag);
        byte[] readBack = new byte[16];
        p.CopyTagTo(readBack);
        Assert.Equal(tag, readBack);
    }

    [Fact]
    public void GcmMessageParams_AbsorbOutput_ReadsWhatTheTokenWrote()
    {
        using var p = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);
        using var scope = new MechanismParameterScope();

        var s = (CK_GCM_MESSAGE_PARAMS)p.BuildMarshalable(scope);

        // Stand in for the token writing the tag into the block it was handed.
        byte[] produced = [.. Enumerable.Range(0, 16).Select(i => (byte)(i + 1))];
        UnmanagedMemory.Write(s.Tag, produced);

        p.AbsorbOutput(s);

        // The public accessor must serve what was absorbed, not the buffer the wrapper started
        // with — reading the wrong one returns an all-zeros tag on every encrypt.
        byte[] readBack = new byte[16];
        p.CopyTagTo(readBack);
        Assert.Equal(produced, readBack);
    }

    [Fact]
    public void CcmMessageParams_AbsorbOutput_ReadsWhatTheTokenWrote()
    {
        using var p = CkmCcmMessageParams.ForEncrypt(dataLen: 64, new byte[13], macBytes: 16);
        using var scope = new MechanismParameterScope();

        var s = (CK_CCM_MESSAGE_PARAMS)p.BuildMarshalable(scope);

        byte[] produced = [.. Enumerable.Range(0, 16).Select(i => (byte)(i + 0x20))];
        UnmanagedMemory.Write(s.Mac, produced);

        p.AbsorbOutput(s);

        byte[] readBack = new byte[16];
        p.CopyMacTo(readBack);
        Assert.Equal(produced, readBack);
    }

    [Fact]
    public void SalsaChaChaPoly1305MessageParams_AbsorbOutput_ReadsWhatTheTokenWrote()
    {
        using var p = CkmSalsa20ChaCha20Poly1305MsgParams.ForEncrypt(new byte[12]);
        using var scope = new MechanismParameterScope();

        var s = (CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS)p.BuildMarshalable(scope);

        byte[] produced = [.. Enumerable.Range(0, 16).Select(i => (byte)(i + 0x40))];
        UnmanagedMemory.Write(s.Tag, produced);

        p.AbsorbOutput(s);

        byte[] readBack = new byte[16];
        p.CopyTagTo(readBack);
        Assert.Equal(produced, readBack);
    }
}
