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
    // Span.CopyTo throws ArgumentException for a short destination too, so the wrapper's own guard
    // is told apart by its message.
    private static void AssertTooSmall(Action copy, int tagLength)
    {
        var e = Assert.Throws<ArgumentException>(copy);
        Assert.Equal("destination", e.ParamName);
        Assert.StartsWith($"Destination must be at least {tagLength} bytes.", e.Message, StringComparison.Ordinal);
    }

    // A destination longer than the tag is fine: the tag fills its start.
    [Fact]
    public void CopyTagTo_LargerDestination_ReceivesTheTagAtItsStart()
    {
        byte[] tag = [.. Enumerable.Range(1, 16).Select(i => (byte)i)];
        byte[] gcm = new byte[20], ccm = new byte[20], poly = new byte[20];

        CkmGcmMessageParams.ForDecrypt(new byte[12], tag).CopyTagTo(gcm);
        CkmCcmMessageParams.ForDecrypt(dataLen: 32, new byte[13], tag).CopyMacTo(ccm);
        CkmSalsa20ChaCha20Poly1305MsgParams.ForDecrypt(new byte[12], tag).CopyTagTo(poly);

        foreach (byte[] destination in (byte[][])[gcm, ccm, poly])
        {
            Assert.Equal(tag, destination[..16]);
            Assert.Equal(new byte[4], destination[16..]);
        }
    }

    [Fact]
    public void SalsaChaChaPoly1305Message_EmptyNonce_Throws()
    {
        var e = Assert.Throws<ArgumentException>(() => CkmSalsa20ChaCha20Poly1305MsgParams.ForEncrypt([]));
        Assert.Equal("nonce", e.ParamName);
    }

    [Fact]
    public void GcmMessage_CopyTagTo_FillsDestination()
    {
        var p = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);
        byte[] tag = new byte[16];
        Assert.Null(Record.Exception(() => p.CopyTagTo(tag))); // tag buffer is allocated; readable
    }

    [Fact]
    public void GcmMessage_CopyTagTo_TooSmall_Throws()
    {
        var p = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);
        AssertTooSmall(() => p.CopyTagTo(new byte[15]), 16);
    }

    [Fact]
    public void GcmMessage_ForDecrypt_RoundTripsCallerTag()
    {
        byte[] tag = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        var p = CkmGcmMessageParams.ForDecrypt(new byte[12], tag);
        byte[] readBack = new byte[16];
        p.CopyTagTo(readBack);
        Assert.Equal(tag, readBack);
    }

    [Fact]
    public void CcmMessage_CopyMacTo_FillsDestination()
    {
        var p = CkmCcmMessageParams.ForEncrypt(dataLen: 64, new byte[13], macBytes: 16);
        Assert.Null(Record.Exception(() => p.CopyMacTo(new byte[16])));
    }

    [Fact]
    public void CcmMessage_CopyMacTo_TooSmall_Throws()
    {
        var p = CkmCcmMessageParams.ForEncrypt(dataLen: 64, new byte[13], macBytes: 16);
        AssertTooSmall(() => p.CopyMacTo(new byte[15]), 16);
    }

    [Fact]
    public void CcmMessage_ForDecrypt_RoundTripsCallerMac()
    {
        byte[] mac = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        var p = CkmCcmMessageParams.ForDecrypt(dataLen: 32, new byte[13], mac);
        byte[] readBack = new byte[16];
        p.CopyMacTo(readBack);
        Assert.Equal(mac, readBack);
    }

    [Fact]
    public void SalsaChaChaPoly1305Message_CopyTagTo_FillsDestination()
    {
        var p = CkmSalsa20ChaCha20Poly1305MsgParams.ForEncrypt(new byte[12]);
        Assert.Null(Record.Exception(() => p.CopyTagTo(new byte[16])));
    }

    [Fact]
    public void SalsaChaChaPoly1305Message_CopyTagTo_TooSmall_Throws()
    {
        var p = CkmSalsa20ChaCha20Poly1305MsgParams.ForEncrypt(new byte[12]);
        AssertTooSmall(() => p.CopyTagTo(new byte[15]), 16);
    }

    [Fact]
    public void SalsaChaChaPoly1305Message_ForDecrypt_RoundTripsCallerTag()
    {
        byte[] tag = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        var p = CkmSalsa20ChaCha20Poly1305MsgParams.ForDecrypt(new byte[12], tag);
        byte[] readBack = new byte[16];
        p.CopyTagTo(readBack);
        Assert.Equal(tag, readBack);
    }

    [Fact]
    public void GcmMessageParams_AbsorbOutput_ReadsWhatTheTokenWrote()
    {
        var p = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);
        using var scope = new MechanismParameterScope();

        Pkcs11ParameterBlock block = p.BuildMarshalable(scope);
        var s = block.Read<CK_GCM_MESSAGE_PARAMS>();

        // Stand in for the token writing the tag into the block it was handed.
        byte[] produced = [.. Enumerable.Range(0, 16).Select(i => (byte)(i + 1))];
        UnmanagedMemory.Write(s.Tag, produced);

        p.AbsorbOutput(block);

        // The public accessor must serve what was absorbed, not the buffer the wrapper started
        // with — reading the wrong one returns an all-zeros tag on every encrypt.
        byte[] readBack = new byte[16];
        p.CopyTagTo(readBack);
        Assert.Equal(produced, readBack);
    }

    [Fact]
    public void CcmMessageParams_AbsorbOutput_ReadsWhatTheTokenWrote()
    {
        var p = CkmCcmMessageParams.ForEncrypt(dataLen: 64, new byte[13], macBytes: 16);
        using var scope = new MechanismParameterScope();

        Pkcs11ParameterBlock block = p.BuildMarshalable(scope);
        var s = block.Read<CK_CCM_MESSAGE_PARAMS>();

        byte[] produced = [.. Enumerable.Range(0, 16).Select(i => (byte)(i + 0x20))];
        UnmanagedMemory.Write(s.Mac, produced);

        p.AbsorbOutput(block);

        byte[] readBack = new byte[16];
        p.CopyMacTo(readBack);
        Assert.Equal(produced, readBack);
    }

    [Fact]
    public void SalsaChaChaPoly1305MessageParams_AbsorbOutput_ReadsWhatTheTokenWrote()
    {
        var p = CkmSalsa20ChaCha20Poly1305MsgParams.ForEncrypt(new byte[12]);
        using var scope = new MechanismParameterScope();

        Pkcs11ParameterBlock block = p.BuildMarshalable(scope);
        var s = block.Read<CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>();

        byte[] produced = [.. Enumerable.Range(0, 16).Select(i => (byte)(i + 0x40))];
        UnmanagedMemory.Write(s.Tag, produced);

        p.AbsorbOutput(block);

        byte[] readBack = new byte[16];
        p.CopyTagTo(readBack);
        Assert.Equal(produced, readBack);
    }
}
