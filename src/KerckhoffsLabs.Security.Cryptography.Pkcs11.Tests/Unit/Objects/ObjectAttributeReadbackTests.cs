using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Objects;

/// <summary>
/// Covers the <see cref="ObjectAttribute"/> read-back validation arms that the happy-path
/// round-trip tests miss: the vendor-id no-value constructor, the wrong-length guards on the
/// scalar/array getters, and the unparseable-date branch of <c>GetValueAsDateTime</c>.
/// </summary>
public sealed class ObjectAttributeReadbackTests
{
    [Fact]
    public void VendorIdCtor_NoValue_HasTypeAndEmptyValue()
    {
        const ulong vendorId = 0x80000001UL;
        using var a = new ObjectAttribute(vendorId);

        Assert.Equal(vendorId, a.Type);
        Assert.Equal(0, a.ValueLength);
        Assert.Empty(a.GetValueAsByteArray());
    }

    [Fact]
    public void CkaCtor_NoValue_HasTypeAndEmptyValue()
    {
        using var a = new ObjectAttribute(CKA.CKA_TOKEN);

        Assert.Equal((ulong)CKA.CKA_TOKEN, a.Type);
        Assert.Equal(0, a.ValueLength);
    }

    [Fact]
    public void GetValueAsBool_WrongLength_Throws()
    {
        // A CK_ULONG-sized value (4/8 bytes) is not a CK_BBOOL (1 byte).
        using var a = new ObjectAttribute(CKA.CKA_VALUE, 5UL);
        Assert.Throws<AttributeValueException>(() => a.GetValueAsBool());
    }

    [Fact]
    public void GetValueAsUlong_WrongLength_Throws()
    {
        using var a = new ObjectAttribute(CKA.CKA_ID, [1, 2, 3]);
        Assert.Throws<AttributeValueException>(() => a.GetValueAsUlong());
    }

    [Fact]
    public void GetValueAsUlongArray_MisalignedLength_Throws()
    {
        // 3 bytes is not a whole number of CK_ULONGs (4 or 8 bytes each).
        using var a = new ObjectAttribute(CKA.CKA_ALLOWED_MECHANISMS, [1, 2, 3]);
        Assert.Throws<AttributeValueException>(() => a.GetValueAsUlongArray());
    }

    [Fact]
    public void GetValueAsAttributeArray_MisalignedLength_Throws()
    {
        // 3 bytes is not a whole number of CK_ATTRIBUTEs.
        using var a = new ObjectAttribute(CKA.CKA_WRAP_TEMPLATE, [1, 2, 3]);
        Assert.Throws<AttributeValueException>(() => a.GetValueAsAttributeArray());
    }

    [Fact]
    public void GetValueAsDateTime_Unparseable_ReturnsNull()
    {
        // 8 bytes (the CK_DATE length) that are not a valid yyyyMMdd date.
        using var a = new ObjectAttribute(CKA.CKA_START_DATE, "ZZZZZZZZ"u8.ToArray());
        Assert.Null(a.GetValueAsDateTime());
    }

    [Fact]
    public void GetValueAsDateTime_ValidDate_ReturnsUtc()
    {
        using var a = new ObjectAttribute(CKA.CKA_START_DATE, "20240115"u8.ToArray());

        DateTime? dt = a.GetValueAsDateTime();

        Assert.NotNull(dt);
        Assert.Equal(new DateTime(2024, 1, 15, 0, 0, 0, DateTimeKind.Utc), dt!.Value);
        Assert.Equal(DateTimeKind.Utc, dt.Value.Kind);
    }

    [Fact]
    public void GetValueAsDateTime_Empty_ReturnsNull()
    {
        using var a = new ObjectAttribute(CKA.CKA_START_DATE, ReadOnlySpan<byte>.Empty);
        Assert.Null(a.GetValueAsDateTime());
    }
}
