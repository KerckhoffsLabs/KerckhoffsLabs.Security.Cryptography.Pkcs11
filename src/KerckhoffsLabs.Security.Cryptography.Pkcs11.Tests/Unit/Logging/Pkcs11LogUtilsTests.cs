using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Logging;

public sealed class Pkcs11LogUtilsTests
{
    [Theory]
    [InlineData(CKU.CKU_SO, "security officer")]
    [InlineData(CKU.CKU_USER, "normal user")]
    [InlineData(CKU.CKU_CONTEXT_SPECIFIC, "context specific user")]
    public void ToString_KnownUserTypes_MapToLabels(CKU userType, string expected)
        => Assert.Equal(expected, Pkcs11LogUtils.ToString(userType));

    [Fact]
    public void ToString_UnknownUserType_FallsBackToEnumToString()
    {
        var unknown = (CKU)99;
        Assert.Equal(unknown.ToString(), Pkcs11LogUtils.ToString(unknown));
    }
}
