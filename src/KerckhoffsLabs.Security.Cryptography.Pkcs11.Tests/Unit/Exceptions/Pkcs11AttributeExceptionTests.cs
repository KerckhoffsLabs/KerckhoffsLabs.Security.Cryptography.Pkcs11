using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Exceptions;

/// <summary>
/// <see cref="Pkcs11AttributeException"/>: the public constructor's defaults, and the internal
/// factory for attribute codes as a module reports them, which must never throw while building the
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
        Assert.IsAssignableFrom<CryptographicException>(ex);
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
    public void For_ADefinedCode_NamesTheAttribute()
    {
        var ex = Pkcs11AttributeException.For((ulong)CKA.CKA_MODULUS);

        Assert.Equal(CKA.CKA_MODULUS, ex.Attribute);
        Assert.Equal("Value of attribute CKA_MODULUS could not be read", ex.Message);
    }

    [Fact]
    public void For_AnUndefinedVendorCode_KeepsTheCodeAndShowsItInHex()
    {
        var ex = Pkcs11AttributeException.For(0x8000_0123UL);

        Assert.Equal((CKA)0x8000_0123u, ex.Attribute);
        Assert.Contains("CKA 0x80000123", ex.Message, StringComparison.Ordinal);
    }

    // The old ulong constructors narrowed with Convert.ToUInt32, so a 64-bit vendor code made the
    // exception constructor itself throw OverflowException in place of the real error.
    [Fact]
    public void For_ACodeWiderThanCka_DoesNotThrow_AndCarriesTheFullCode()
    {
        var ex = Pkcs11AttributeException.For(0x1_8000_0001UL, innerException: new FormatException());

        Assert.Equal(CKA.CKA_VENDOR_DEFINED, ex.Attribute);
        Assert.Contains("CKA 0x180000001", ex.Message, StringComparison.Ordinal);
        Assert.Contains("could not be converted", ex.Message, StringComparison.Ordinal);
    }
}
