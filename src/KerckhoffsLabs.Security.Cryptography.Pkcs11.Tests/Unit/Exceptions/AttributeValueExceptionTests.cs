using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Exceptions;

/// <summary>
/// Covers every <see cref="AttributeValueException"/> constructor (CKA / uint / ulong, with and
/// without an inner exception): the <see cref="AttributeValueException.Attribute"/> round-trip, the
/// "could not be read" vs. "could not be converted" message selection, and inner-exception wiring.
/// </summary>
public sealed class AttributeValueExceptionTests
{
    private const CKA Attr = CKA.CKA_VALUE;

    [Fact]
    public void CkaCtor_SetsAttribute_AndReadMessage()
    {
        var ex = new AttributeValueException(Attr);

        Assert.Equal(Attr, ex.Attribute);
        Assert.Null(ex.InnerException);
        Assert.Contains("could not be read", ex.Message);
        Assert.Contains(Attr.ToString(), ex.Message);
    }

    [Fact]
    public void CkaCtor_WithInner_SetsInner_AndConvertedMessage()
    {
        var inner = new InvalidOperationException("boom");
        var ex = new AttributeValueException(Attr, inner);

        Assert.Equal(Attr, ex.Attribute);
        Assert.Same(inner, ex.InnerException);
        Assert.Contains("could not be converted", ex.Message);
        Assert.Contains(Attr.ToString(), ex.Message);
    }

    [Fact]
    public void UintCtor_MapsToAttribute()
    {
        var ex = new AttributeValueException((uint)Attr);

        Assert.Equal(Attr, ex.Attribute);
        Assert.Null(ex.InnerException);
        Assert.Contains("could not be read", ex.Message);
    }

    [Fact]
    public void UintCtor_WithInner_MapsToAttribute_AndSetsInner()
    {
        var inner = new FormatException("bad");
        var ex = new AttributeValueException((uint)Attr, inner);

        Assert.Equal(Attr, ex.Attribute);
        Assert.Same(inner, ex.InnerException);
        Assert.Contains("could not be converted", ex.Message);
    }

    [Fact]
    public void UlongCtor_MapsToAttribute()
    {
        var ex = new AttributeValueException((ulong)Attr);

        Assert.Equal(Attr, ex.Attribute);
        Assert.Null(ex.InnerException);
        Assert.Contains("could not be read", ex.Message);
    }

    [Fact]
    public void UlongCtor_WithInner_MapsToAttribute_AndSetsInner()
    {
        var inner = new OverflowException("over");
        var ex = new AttributeValueException((ulong)Attr, inner);

        Assert.Equal(Attr, ex.Attribute);
        Assert.Same(inner, ex.InnerException);
        Assert.Contains("could not be converted", ex.Message);
    }

    // The ulong overloads narrow via Convert.ToUInt32, which throws on values that don't fit.
    [Fact]
    public void UlongCtor_OutOfUintRange_Throws() =>
        Assert.Throws<OverflowException>(() => new AttributeValueException(ulong.MaxValue));
}
