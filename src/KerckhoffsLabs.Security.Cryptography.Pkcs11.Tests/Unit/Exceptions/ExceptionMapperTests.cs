using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Exceptions;

public class ExceptionMapperTests
{
    public static IEnumerable<object[]> AuthenticationCases() =>
    [
        [CKR.CKR_PIN_INCORRECT],
        [CKR.CKR_PIN_INVALID],
        [CKR.CKR_PIN_LEN_RANGE],
        [CKR.CKR_PIN_EXPIRED],
        [CKR.CKR_PIN_LOCKED],
        [CKR.CKR_PIN_TOO_WEAK],
        [CKR.CKR_USER_ALREADY_LOGGED_IN],
        [CKR.CKR_USER_NOT_LOGGED_IN],
        [CKR.CKR_USER_PIN_NOT_INITIALIZED],
        [CKR.CKR_USER_TYPE_INVALID],
        [CKR.CKR_USER_ANOTHER_ALREADY_LOGGED_IN],
        [CKR.CKR_USER_TOO_MANY_TYPES],
    ];

    [Theory]
    [MemberData(nameof(AuthenticationCases))]
    public void Map_PinAndUserCkr_ReturnsAuthenticationException(CKR ckr)
    {
        var ex = ExceptionMapper.Map(ckr, "C_Login");

        Assert.IsType<Pkcs11AuthenticationException>(ex);
        Assert.Equal(ckr, ex.ReturnValue);
        Assert.Equal("C_Login", ex.Method);
    }

    public static IEnumerable<object[]> SessionCases() =>
    [
        [CKR.CKR_SESSION_CLOSED],
        [CKR.CKR_SESSION_COUNT],
        [CKR.CKR_SESSION_HANDLE_INVALID],
        [CKR.CKR_SESSION_PARALLEL_NOT_SUPPORTED],
        [CKR.CKR_SESSION_READ_ONLY],
        [CKR.CKR_SESSION_EXISTS],
        [CKR.CKR_SESSION_READ_ONLY_EXISTS],
        [CKR.CKR_SESSION_READ_WRITE_SO_EXISTS],
    ];

    [Theory]
    [MemberData(nameof(SessionCases))]
    public void Map_SessionCkr_ReturnsSessionException(CKR ckr)
        => Assert.IsType<Pkcs11SessionException>(ExceptionMapper.Map(ckr, "C_OpenSession"));

    public static IEnumerable<object[]> TokenCases() =>
    [
        [CKR.CKR_TOKEN_NOT_PRESENT],
        [CKR.CKR_TOKEN_NOT_RECOGNIZED],
        [CKR.CKR_TOKEN_WRITE_PROTECTED],
        [CKR.CKR_TOKEN_RESOURCE_EXCEEDED],
        [CKR.CKR_DEVICE_ERROR],
        [CKR.CKR_DEVICE_MEMORY],
        [CKR.CKR_DEVICE_REMOVED],
    ];

    [Theory]
    [MemberData(nameof(TokenCases))]
    public void Map_TokenAndDeviceCkr_ReturnsTokenException(CKR ckr)
        => Assert.IsType<Pkcs11TokenException>(ExceptionMapper.Map(ckr, "C_GetTokenInfo"));

    public static IEnumerable<object[]> MechanismCases() =>
    [
        [CKR.CKR_MECHANISM_INVALID],
        [CKR.CKR_MECHANISM_PARAM_INVALID],
        [CKR.CKR_KEY_FUNCTION_NOT_PERMITTED],
    ];

    [Theory]
    [MemberData(nameof(MechanismCases))]
    public void Map_MechanismCkr_ReturnsMechanismException(CKR ckr)
        => Assert.IsType<Pkcs11MechanismException>(ExceptionMapper.Map(ckr, "C_SignInit"));

    public static IEnumerable<object[]> ObjectCases() =>
    [
        [CKR.CKR_OBJECT_HANDLE_INVALID],
        [CKR.CKR_ATTRIBUTE_READ_ONLY],
        [CKR.CKR_ATTRIBUTE_SENSITIVE],
        [CKR.CKR_ATTRIBUTE_TYPE_INVALID],
        [CKR.CKR_ATTRIBUTE_VALUE_INVALID],
    ];

    [Theory]
    [MemberData(nameof(ObjectCases))]
    public void Map_ObjectAndAttributeCkr_ReturnsObjectException(CKR ckr)
        => Assert.IsType<Pkcs11ObjectException>(ExceptionMapper.Map(ckr, "C_DestroyObject"));

    public static IEnumerable<object[]> ArgumentCases() =>
    [
        [CKR.CKR_ARGUMENTS_BAD],
        [CKR.CKR_DATA_INVALID],
        [CKR.CKR_DATA_LEN_RANGE],
        [CKR.CKR_BUFFER_TOO_SMALL],
    ];

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

    [Fact]
    public void Map_PreservesMethodAndCkr()
    {
        var ex = ExceptionMapper.Map(CKR.CKR_PIN_INCORRECT, "C_Login");

        Assert.Equal(CKR.CKR_PIN_INCORRECT, ex.ReturnValue);
        Assert.Equal("C_Login", ex.Method);
    }
}
