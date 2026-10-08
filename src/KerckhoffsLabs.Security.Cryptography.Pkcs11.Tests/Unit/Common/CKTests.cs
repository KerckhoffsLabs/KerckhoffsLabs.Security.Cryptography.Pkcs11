using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Common;

/// <summary>
/// <see cref="CK.CK_UNAVAILABLE_INFORMATION"/> is all bits set in a <c>CK_ULONG</c>, whose width is not
/// the same everywhere: 32-bit on Windows, pointer-sized elsewhere. The expected value here is derived
/// from the platform, not from the interop type the constant is computed from.
/// </summary>
public sealed class CKTests
{
    private static readonly ulong AllBitsOfACkULong =
        OperatingSystem.IsWindows() || IntPtr.Size == sizeof(uint) ? uint.MaxValue : ulong.MaxValue;

    [Fact]
    public void UnavailableInformation_IsAllBitsOfThePlatformsCkULong()
        => Assert.Equal(AllBitsOfACkULong, CK.CK_UNAVAILABLE_INFORMATION);

    [Fact]
    public void IsCkInformationUnavailable_RecognisesOnlyTheSentinel()
    {
        Assert.True(CK.IsCkInformationUnavailable(AllBitsOfACkULong));
        Assert.False(CK.IsCkInformationUnavailable(0));
        Assert.False(CK.IsCkInformationUnavailable(AllBitsOfACkULong - 1));
    }

    // Where CK_ULONG is 64-bit, a value that is all ones only in its low 32 bits is a real length, not
    // the sentinel.
    [Fact]
    public void IsCkInformationUnavailable_On64BitCkULong_DoesNotTakeA32BitAllOnesValueForTheSentinel()
    {
        Assert.SkipWhen(AllBitsOfACkULong == uint.MaxValue, "CK_ULONG is 32-bit on this platform.");
        Assert.False(CK.IsCkInformationUnavailable(uint.MaxValue));
    }
}
