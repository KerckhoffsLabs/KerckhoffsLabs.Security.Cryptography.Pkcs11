using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

public sealed class CkMechanismTests
{
    [Fact]
    public void CreateMechanism_SpanAndByteArrayOverloads_ProduceIdenticalBuffers()
    {
        byte[] paramBytes = [0x10, 0x20, 0x30];

        CK_MECHANISM fromArray = CK_MECHANISM.CreateMechanism(CKM.CKM_AES_GCM, paramBytes);
        CK_MECHANISM fromSpan = CK_MECHANISM.CreateMechanism(CKM.CKM_AES_GCM, (ReadOnlySpan<byte>)paramBytes);

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
