using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Exceptions;

public sealed class Pkcs11AmbiguousTokenExceptionTests
{
    [Fact]
    public void Ctor_ExposesMethodMessageAndSlots_WithCkrOk()
    {
        SlotId[] slots = [new(1), new(4)];

        var ex = new Pkcs11AmbiguousTokenException("C_GetTokenInfo", "two tokens match", slots);

        Assert.Equal(CKR.CKR_OK, ex.ReturnValue);
        Assert.Equal("C_GetTokenInfo", ex.Method);
        Assert.Equal("two tokens match", ex.Message);
        Assert.Equal(slots, ex.SlotIds);
        Assert.IsType<Pkcs11Exception>(ex, exactMatch: false);
    }

    [Fact]
    public void Ctor_NullMessage_FallsBackToTheDefault()
    {
        var ex = new Pkcs11AmbiguousTokenException("C_GetTokenInfo", null, [new(1), new(2)]);

        Assert.Contains("C_GetTokenInfo", ex.Message);
    }

    // A null list is normalized, so a handler can enumerate SlotIds without a null check.
    [Fact]
    public void Ctor_NullSlotIds_BecomesEmpty()
    {
        var ex = new Pkcs11AmbiguousTokenException("C_GetTokenInfo", null, null!);

        Assert.NotNull(ex.SlotIds);
        Assert.Empty(ex.SlotIds);
    }

    [Fact]
    public void Ctor_NullMethod_Throws()
        => Assert.Equal("method", Assert.Throws<ArgumentNullException>(
            () => new Pkcs11AmbiguousTokenException(null!, null, [])).ParamName);
}
