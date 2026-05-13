using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

public class Pkcs11ExceptionTests
{
    [Fact]
    public void ReturnValue_ExposesCkr()
    {
        var ex = new Pkcs11AuthenticationException(CKR.CKR_PIN_INCORRECT, "C_Login", null);

        Assert.Equal(CKR.CKR_PIN_INCORRECT, ex.ReturnValue);
        Assert.Equal("C_Login", ex.Method);
    }

    [Fact]
    public void NewCtor_DefaultMessage_MentionsMethodAndCkr()
    {
        var ex = new Pkcs11TokenException(CKR.CKR_DEVICE_ERROR, "C_OpenSession", null);

        Assert.Contains("C_OpenSession", ex.Message);
        Assert.Contains("CKR_DEVICE_ERROR", ex.Message);
    }

    [Fact]
    public void NewCtor_ExplicitMessage_OverridesDefault()
    {
        var ex = new Pkcs11TokenException(CKR.CKR_DEVICE_ERROR, "C_OpenSession", "boom");

        Assert.Equal("boom", ex.Message);
    }

    [Fact]
    public void AuthenticationException_DerivesFromPkcs11Exception()
    {
        var ex = new Pkcs11AuthenticationException(CKR.CKR_PIN_INCORRECT, "C_Login", null);

        Assert.IsAssignableFrom<Pkcs11Exception>(ex);
        Assert.Equal(CKR.CKR_PIN_INCORRECT, ex.ReturnValue);
    }

    [Fact]
    public void SessionException_DerivesFromPkcs11Exception()
        => Assert.IsAssignableFrom<Pkcs11Exception>(
            new Pkcs11SessionException(CKR.CKR_SESSION_HANDLE_INVALID, "C_GetSessionInfo", null));

    [Fact]
    public void TokenException_DerivesFromPkcs11Exception()
        => Assert.IsAssignableFrom<Pkcs11Exception>(
            new Pkcs11TokenException(CKR.CKR_TOKEN_NOT_PRESENT, "C_GetTokenInfo", null));

    [Fact]
    public void MechanismException_DerivesFromPkcs11Exception()
        => Assert.IsAssignableFrom<Pkcs11Exception>(
            new Pkcs11MechanismException(CKR.CKR_MECHANISM_INVALID, "C_SignInit", null));

    [Fact]
    public void ObjectException_DerivesFromPkcs11Exception()
        => Assert.IsAssignableFrom<Pkcs11Exception>(
            new Pkcs11ObjectException(CKR.CKR_OBJECT_HANDLE_INVALID, "C_DestroyObject", null));

    [Fact]
    public void ArgumentException_DerivesFromPkcs11Exception()
        => Assert.IsAssignableFrom<Pkcs11Exception>(
            new Pkcs11ArgumentException(CKR.CKR_ARGUMENTS_BAD, "C_GenerateKey", null));

    [Fact]
    public void UnclassifiedException_DerivesFromPkcs11Exception()
        => Assert.IsAssignableFrom<Pkcs11Exception>(
            new Pkcs11UnclassifiedException(CKR.CKR_GENERAL_ERROR, "C_Finalize", null));

    [Fact]
    public void ThrowIfError_CkrOk_DoesNotThrow()
    {
        // Should return without throwing.
        Pkcs11Exception.ThrowIfError(CKR.CKR_OK, "C_Initialize");
    }

    [Fact]
    public void ThrowIfError_AuthenticationCkr_ThrowsTypedSubclass()
    {
        var ex = Assert.Throws<Pkcs11AuthenticationException>(
            () => Pkcs11Exception.ThrowIfError(CKR.CKR_PIN_INCORRECT, "C_Login"));

        Assert.Equal(CKR.CKR_PIN_INCORRECT, ex.ReturnValue);
        Assert.Equal("C_Login", ex.Method);
    }

    [Fact]
    public void ThrowIfError_UncategorizedCkr_ThrowsUnclassified()
    {
        var ex = Assert.Throws<Pkcs11UnclassifiedException>(
            () => Pkcs11Exception.ThrowIfError(CKR.CKR_GENERAL_ERROR, "C_Finalize"));

        Assert.Equal(CKR.CKR_GENERAL_ERROR, ex.ReturnValue);
    }

    [Fact]
    public void ThrowIfError_TypedExceptionIsAlsoBasePkcs11Exception()
    {
        // Existing catch (Pkcs11Exception) clauses across the codebase continue to work.
        var ex = Assert.Throws<Pkcs11AuthenticationException>(
            () => Pkcs11Exception.ThrowIfError(CKR.CKR_PIN_INCORRECT, "C_Login"));

        Assert.IsAssignableFrom<Pkcs11Exception>(ex);
    }
}
