using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Exceptions;

public sealed class ExceptionMapperTests
{
    public static TheoryData<CKR> AuthenticationCases() => new(
        CKR.CKR_PIN_INCORRECT,
        CKR.CKR_PIN_INVALID,
        CKR.CKR_PIN_LEN_RANGE,
        CKR.CKR_PIN_EXPIRED,
        CKR.CKR_PIN_LOCKED,
        CKR.CKR_PIN_TOO_WEAK,
        CKR.CKR_USER_ALREADY_LOGGED_IN,
        CKR.CKR_USER_NOT_LOGGED_IN,
        CKR.CKR_USER_PIN_NOT_INITIALIZED,
        CKR.CKR_USER_TYPE_INVALID,
        CKR.CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
        CKR.CKR_USER_TOO_MANY_TYPES);

    [Theory]
    [MemberData(nameof(AuthenticationCases))]
    public void Map_PinAndUserCkr_ReturnsAuthenticationException(CKR ckr)
    {
        var ex = ExceptionMapper.Map(ckr, "C_Login");

        Assert.IsType<Pkcs11AuthenticationException>(ex);
        Assert.Equal(ckr, ex.ReturnValue);
        Assert.Equal("C_Login", ex.Method);
    }

    public static TheoryData<CKR> SessionCases() => new(
        CKR.CKR_SESSION_CLOSED,
        CKR.CKR_SESSION_COUNT,
        CKR.CKR_SESSION_HANDLE_INVALID,
        CKR.CKR_SESSION_PARALLEL_NOT_SUPPORTED,
        CKR.CKR_SESSION_READ_ONLY,
        CKR.CKR_SESSION_EXISTS,
        CKR.CKR_SESSION_READ_ONLY_EXISTS,
        CKR.CKR_SESSION_READ_WRITE_SO_EXISTS);

    [Theory]
    [MemberData(nameof(SessionCases))]
    public void Map_SessionCkr_ReturnsSessionException(CKR ckr)
        => Assert.IsType<Pkcs11SessionException>(ExceptionMapper.Map(ckr, "C_OpenSession"));

    public static TheoryData<CKR> TokenCases() => new(
        CKR.CKR_TOKEN_NOT_PRESENT,
        CKR.CKR_TOKEN_NOT_RECOGNIZED,
        CKR.CKR_TOKEN_WRITE_PROTECTED,
        CKR.CKR_TOKEN_RESOURCE_EXCEEDED,
        CKR.CKR_DEVICE_ERROR,
        CKR.CKR_DEVICE_MEMORY,
        CKR.CKR_DEVICE_REMOVED);

    [Theory]
    [MemberData(nameof(TokenCases))]
    public void Map_TokenAndDeviceCkr_ReturnsTokenException(CKR ckr)
        => Assert.IsType<Pkcs11TokenException>(ExceptionMapper.Map(ckr, "C_GetTokenInfo"));

    public static TheoryData<CKR> MechanismCases() => new(
        CKR.CKR_MECHANISM_INVALID,
        CKR.CKR_MECHANISM_PARAM_INVALID,
        CKR.CKR_KEY_FUNCTION_NOT_PERMITTED);

    [Theory]
    [MemberData(nameof(MechanismCases))]
    public void Map_MechanismCkr_ReturnsMechanismException(CKR ckr)
        => Assert.IsType<Pkcs11MechanismException>(ExceptionMapper.Map(ckr, "C_SignInit"));

    public static TheoryData<CKR> ObjectCases() => new(
        CKR.CKR_OBJECT_HANDLE_INVALID,
        CKR.CKR_ATTRIBUTE_READ_ONLY,
        CKR.CKR_ATTRIBUTE_SENSITIVE,
        CKR.CKR_ATTRIBUTE_TYPE_INVALID,
        CKR.CKR_ATTRIBUTE_VALUE_INVALID);

    [Theory]
    [MemberData(nameof(ObjectCases))]
    public void Map_ObjectAndAttributeCkr_ReturnsObjectException(CKR ckr)
        => Assert.IsType<Pkcs11ObjectException>(ExceptionMapper.Map(ckr, "C_DestroyObject"));

    public static TheoryData<CKR> ArgumentCases() => new(
        CKR.CKR_ARGUMENTS_BAD,
        CKR.CKR_DATA_INVALID,
        CKR.CKR_DATA_LEN_RANGE,
        CKR.CKR_BUFFER_TOO_SMALL);

    [Theory]
    [MemberData(nameof(ArgumentCases))]
    public void Map_ArgumentCkr_ReturnsArgumentException(CKR ckr)
        => Assert.IsType<Pkcs11ArgumentException>(ExceptionMapper.Map(ckr, "C_GenerateKey"));

    [Theory]
    [InlineData(CKR.CKR_GENERAL_ERROR)]
    [InlineData(CKR.CKR_FUNCTION_FAILED)]
    [InlineData(CKR.CKR_HOST_MEMORY)]
    [InlineData(CKR.CKR_CRYPTOKI_NOT_INITIALIZED)]
    public void Map_UncategorizedCkr_ReturnsUnclassifiedException(CKR ckr)
        => Assert.IsType<Pkcs11UnclassifiedException>(ExceptionMapper.Map(ckr, "C_Finalize"));

    // Vendor-defined codes (≥ CKR_VENDOR_DEFINED) and codes newer than the CKR enum are
    // spec-legal on the return path. They must land in the typed hierarchy with the raw
    // code preserved and rendered as hex — not escape as a bare InvalidEnumValueException.
    [Theory]
    [InlineData(0x80000123u)]
    [InlineData(0xF0001000u)]
    public void Map_VendorDefinedCkr_ReturnsUnclassifiedWithRawCodeAndHexMessage(uint raw)
    {
        var ckr = (CKR)raw;

        var ex = ExceptionMapper.Map(ckr, "C_Sign");

        Assert.IsType<Pkcs11UnclassifiedException>(ex);
        Assert.Equal(raw, (uint)ex.ReturnValue);
        Assert.Equal("C_Sign", ex.Method);
        Assert.Contains($"vendor-defined CKR 0x{raw:X8}", ex.Message);
    }

    // Exactly CKR_VENDOR_DEFINED is itself a named member (the range sentinel), so it prints
    // by name like any defined code — only values beyond it fall back to hex.
    [Fact]
    public void Map_VendorDefinedSentinel_PrintsEnumName()
        => Assert.Contains("CKR_VENDOR_DEFINED",
            ExceptionMapper.Map(CKR.CKR_VENDOR_DEFINED, "C_Sign").Message);

    [Fact]
    public void Map_UnrecognizedNonVendorCkr_ReturnsUnclassifiedWithRawCodeAndHexMessage()
    {
        var ckr = (CKR)0x0000FFFFu; // e.g. a code from a future spec revision

        var ex = ExceptionMapper.Map(ckr, "C_Sign");

        Assert.IsType<Pkcs11UnclassifiedException>(ex);
        Assert.Equal(0x0000FFFFu, (uint)ex.ReturnValue);
        Assert.Contains("unrecognized CKR 0x0000FFFF", ex.Message);
    }

    [Fact]
    public void ThrowIfError_VendorDefinedCkr_ThrowsTypedPkcs11Exception()
    {
        var ckr = (CKR)0x80000042u;

        var ex = Assert.ThrowsAny<Pkcs11Exception>(
            () => Pkcs11Exception.ThrowIfError(ckr, "C_GenerateKeyPair"));

        Assert.Equal(ckr, ex.ReturnValue);
    }
}
