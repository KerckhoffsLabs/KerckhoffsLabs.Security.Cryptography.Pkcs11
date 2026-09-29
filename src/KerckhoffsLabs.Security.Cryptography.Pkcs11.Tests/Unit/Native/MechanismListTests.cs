using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// The conversion from the native <c>CK_MECHANISM_TYPE</c> list to the <see cref="CKM"/>-typed list that
/// <c>C_GetMechanismList</c> returns.
/// </summary>
public sealed class MechanismListTests
{
    public static bool NativeULongIs64Bit => UnmanagedMemory.NativeULongSize == sizeof(ulong);

    private static NativeCULong[] Native(params ulong[] values) => [.. values.Select(v => (NativeCULong)v)];

    [Fact]
    public void Copy_KeepsStandardAndVendorValues_InOrder()
    {
        NativeCULong[] native = Native((ulong)CKM.CKM_AES_GCM, 0x8000_1234UL, (ulong)CKM.CKM_SHA256);
        var destination = new CKM[3];

        int kept = MechanismList.CopyRepresentable(native, returned: 3, destination);

        Assert.Equal(3, kept);
        Assert.Equal([CKM.CKM_AES_GCM, (CKM)0x8000_1234U, CKM.CKM_SHA256], destination);
    }

    [Fact]
    public void Copy_ReadsOnlyTheEntriesTheModuleReturned()
    {
        NativeCULong[] native = Native((ulong)CKM.CKM_AES_GCM, (ulong)CKM.CKM_SHA256, 0);
        var destination = new CKM[3];

        int kept = MechanismList.CopyRepresentable(native, returned: 2, destination);

        Assert.Equal(2, kept);
        Assert.Equal([CKM.CKM_AES_GCM, CKM.CKM_SHA256], destination.AsSpan(0, kept).ToArray());
    }

    [Fact(SkipUnless = nameof(NativeULongIs64Bit), Skip = "CK_ULONG is 32 bits on this platform")]
    public void Copy_DropsValuesWiderThanCkm_AndCompacts()
    {
        NativeCULong[] native = Native((ulong)CKM.CKM_AES_GCM, 0x1_8000_0001UL, (ulong)CKM.CKM_SHA256);
        var destination = new CKM[3];

        int kept = MechanismList.CopyRepresentable(native, returned: 3, destination);

        Assert.Equal(2, kept);
        Assert.Equal([CKM.CKM_AES_GCM, CKM.CKM_SHA256], destination.AsSpan(0, kept).ToArray());
    }
}
