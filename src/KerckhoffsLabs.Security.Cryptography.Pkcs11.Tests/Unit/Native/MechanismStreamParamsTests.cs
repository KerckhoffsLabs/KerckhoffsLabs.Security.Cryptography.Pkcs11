using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>Marshalling round trips for the Stream / AEAD nonce params.</summary>
public sealed class MechanismStreamParamsTests
{
    [Fact]
    public void Salsa20_MarshalsBlockCounterAndNonce()
    {
        byte[] blockCounter = [0, 0, 0, 0, 0, 0, 0, 1];
        byte[] nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        var p = new CkmSalsa20Params(blockCounter, nonce, nonceBits: 64);
        using var scope = new MechanismParameterScope();
        var s = p.BuildMarshalable(scope).Read<CK_SALSA20_PARAMS>();

        Assert.Equal(blockCounter, UnmanagedMemory.Read(s.BlockCounter, blockCounter.Length));
        Assert.Equal(nonce, UnmanagedMemory.Read(s.Nonce, nonce.Length));
        Assert.Equal(64UL, (ulong)s.NonceBits);
    }

    [Fact]
    public void Salsa20_RejectsEmptyBlockCounter() =>
        Assert.Throws<ArgumentException>(() => new CkmSalsa20Params(default, new byte[8], 64));

    [Fact]
    public void Salsa20_RejectsEmptyNonce() =>
        Assert.Throws<ArgumentException>(() => new CkmSalsa20Params(new byte[8], default, 64));

    // CK_SALSA20_PARAMS carries no length field for the block counter — the module always reads 8
    // bytes from the pointer — and reads nonceBits/8 bytes from the nonce pointer regardless of the
    // buffer's actual length. Either mismatch is an out-of-bounds read on the token.

    [Theory]
    [InlineData(4)]
    [InlineData(7)]
    [InlineData(9)]
    [InlineData(16)]
    public void Salsa20_RejectsWrongBlockCounterLength(int length) =>
        Assert.Throws<ArgumentException>(() => new CkmSalsa20Params(new byte[length], new byte[8], 64));

    [Theory]
    [InlineData(32)]
    [InlineData(96)]
    public void Salsa20_RejectsInvalidNonceBits(int nonceBits) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => new CkmSalsa20Params(new byte[8], new byte[8], nonceBits));

    [Fact]
    public void Salsa20_RejectsNonceBitsExceedingBufferLength() =>
        // 64 bits (8 bytes) declared, but the buffer is only 4 bytes.
        Assert.Throws<ArgumentOutOfRangeException>(() => new CkmSalsa20Params(new byte[8], new byte[4], 64));

    [Fact]
    public void SalsaChaChaPoly1305_MarshalsNonceAndAad()
    {
        byte[] nonce = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        byte[] aad = [0xAA, 0xBB];
        var p = new CkmSalsa20ChaCha20Poly1305Params(nonce, aad);
        using var scope = new MechanismParameterScope();
        var s = p.BuildMarshalable(scope).Read<CK_SALSA20_CHACHA20_POLY1305_PARAMS>();

        Assert.Equal((ulong)nonce.Length, (ulong)s.NonceLen);
        Assert.Equal(nonce, UnmanagedMemory.Read(s.Nonce, nonce.Length));
        Assert.Equal((ulong)aad.Length, (ulong)s.AADLen);
        Assert.Equal(aad, UnmanagedMemory.Read(s.AAD, aad.Length));
    }

    [Fact]
    public void SalsaChaChaPoly1305_EmptyAad_NullPointer()
    {
        byte[] nonce = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        var p = new CkmSalsa20ChaCha20Poly1305Params(nonce, default);
        using var scope = new MechanismParameterScope();
        var s = p.BuildMarshalable(scope).Read<CK_SALSA20_CHACHA20_POLY1305_PARAMS>();

        Assert.Equal(0UL, (ulong)s.AADLen);
        Assert.Equal(IntPtr.Zero, s.AAD);
    }

    [Fact]
    public void SalsaChaChaPoly1305_RejectsEmptyNonce() =>
        Assert.Throws<ArgumentException>(() => new CkmSalsa20ChaCha20Poly1305Params(default, default));
}
