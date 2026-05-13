// Licensed under the MIT License

using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

public class SpanOverloadSmokeTests
{
    [Fact]
    public void ObjectAttribute_SpanCtor_ProducesIdenticalBufferToByteArrayCtor()
    {
        byte[] payload = [1, 2, 3, 4, 5];

        using var fromArray = new ObjectAttribute(CKA.CKA_VALUE, payload);
        using var fromSpan  = new ObjectAttribute(CKA.CKA_VALUE, (ReadOnlySpan<byte>)payload);

        Assert.Equal(fromArray.ValueLength, fromSpan.ValueLength);

        byte[] readBackArray = fromArray.GetValueAsByteArray();
        byte[] readBackSpan  = fromSpan.GetValueAsByteArray();
        Assert.Equal(readBackArray, readBackSpan);
        Assert.Equal(payload, readBackArray);
    }

    [Fact]
    public void ObjectAttribute_CopyValueTo_WritesExactBytesAndReturnsCount()
    {
        byte[] payload = [9, 8, 7];
        using var attr = new ObjectAttribute(CKA.CKA_VALUE, payload);

        Span<byte> destination = stackalloc byte[8];
        int written = attr.CopyValueTo(destination);

        Assert.Equal(payload.Length, written);
        Assert.Equal(payload, destination[..written].ToArray());
    }

    [Fact]
    public void ObjectAttribute_CopyValueTo_ThrowsWhenDestinationTooSmall()
    {
        byte[] payload = [1, 2, 3, 4, 5];
        using var attr = new ObjectAttribute(CKA.CKA_VALUE, payload);

        byte[] tooSmall = new byte[3];
        Assert.Throws<ArgumentException>(() => attr.CopyValueTo(tooSmall));
    }

    [Fact]
    public void ObjectAttribute_DoubleDisposeIsSafe()
    {
        var attr = new ObjectAttribute(CKA.CKA_VALUE, new byte[] { 1, 2, 3 });
        attr.Dispose();
        attr.Dispose(); // must not throw
    }

    [Fact]
    public void ObjectAttribute_PostDisposeAccess_Throws()
    {
        var attr = new ObjectAttribute(CKA.CKA_VALUE, new byte[] { 1, 2, 3 });
        attr.Dispose();
        Assert.Throws<ObjectDisposedException>(() => attr.GetValueAsByteArray());
    }

    [Fact]
    public void CKMechanism_SpanCtor_ProducesIdenticalBufferToByteArrayCtor()
    {
        byte[] paramBytes = [0x10, 0x20, 0x30];

        CK_MECHANISM fromArray = CK_MECHANISM.CreateMechanism(CKM.CKM_AES_GCM, paramBytes);
        CK_MECHANISM fromSpan  = CK_MECHANISM.CreateMechanism(CKM.CKM_AES_GCM, (ReadOnlySpan<byte>)paramBytes);

        try
        {
            Assert.Equal(fromArray.Mechanism, fromSpan.Mechanism);
            Assert.Equal((int)fromArray.ParameterLen, (int)fromSpan.ParameterLen);

            byte[] aBytes = new byte[(int)fromArray.ParameterLen];
            byte[] bBytes = new byte[(int)fromSpan.ParameterLen];
            UnmanagedMemory.Read(fromArray.Parameter, aBytes);
            UnmanagedMemory.Read(fromSpan.Parameter, bBytes);
            Assert.Equal(aBytes, bBytes);
            Assert.Equal(paramBytes, aBytes);
        }
        finally
        {
            UnmanagedMemory.Free(ref fromArray.Parameter);
            UnmanagedMemory.Free(ref fromSpan.Parameter);
        }
    }
}
