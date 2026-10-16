using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Exceptions;

/// <summary>
/// <see cref="Pkcs11AttributeException"/>: the constructor's defaults, and attribute codes as a module
/// reports them — vendor-defined or wider than 32 bits — which must never throw while building the
/// exception.
/// </summary>
public sealed class Pkcs11AttributeExceptionTests
{
    [Fact]
    public void Constructor_WithoutMessage_SaysTheValueCouldNotBeRead()
    {
        var ex = new Pkcs11AttributeException(CKA.CKA_VALUE);

        Assert.Equal(CKA.CKA_VALUE, ex.Attribute);
        Assert.Equal("Value of attribute CKA_VALUE could not be read", ex.Message);
        Assert.Null(ex.InnerException);
        Assert.IsType<CryptographicException>(ex, exactMatch: false);
    }

    [Fact]
    public void Constructor_WithInnerException_SaysTheValueCouldNotBeConverted()
    {
        var inner = new FormatException();

        var ex = new Pkcs11AttributeException(CKA.CKA_VALUE, innerException: inner);

        Assert.Equal("Value of attribute CKA_VALUE could not be converted", ex.Message);
        Assert.Same(inner, ex.InnerException);
    }

    [Fact]
    public void Constructor_WithMessage_UsesIt()
    {
        var ex = new Pkcs11AttributeException(CKA.CKA_LABEL, "custom reason");

        Assert.Equal(CKA.CKA_LABEL, ex.Attribute);
        Assert.Equal("custom reason", ex.Message);
    }

    [Fact]
    public void AnUndefinedVendorAttribute_IsKeptAndShownInHex()
    {
        var ex = new Pkcs11AttributeException((CKA)0x8000_0123UL);

        Assert.Equal((CKA)0x8000_0123UL, ex.Attribute);
        Assert.Contains("CKA 0x80000123", ex.Message, StringComparison.Ordinal);
    }

    // CKA is as wide as CK_ULONG, so an attribute code wider than 32 bits (legal where CK_ULONG is 64
    // bits) is carried exactly; building the exception never narrows it.
    [Fact]
    public void AnAttributeWiderThan32Bits_IsCarriedExactly()
    {
        var ex = new Pkcs11AttributeException((CKA)0x1_8000_0001UL, innerException: new FormatException());

        Assert.Equal((CKA)0x1_8000_0001UL, ex.Attribute);
        Assert.Contains("CKA 0x180000001", ex.Message, StringComparison.Ordinal);
        Assert.Contains("could not be converted", ex.Message, StringComparison.Ordinal);
    }
}
