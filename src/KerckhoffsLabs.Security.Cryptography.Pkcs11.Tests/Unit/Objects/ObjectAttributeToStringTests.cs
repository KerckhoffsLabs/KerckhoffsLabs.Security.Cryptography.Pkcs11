using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Objects;

/// <summary>
/// <see cref="ObjectAttribute.ToString"/> names the attribute and prints its value only for flags,
/// types and sizes. Byte and string values — key material, labels, identifiers — must never appear,
/// so templates can go into logs and test-failure output.
/// </summary>
public sealed class ObjectAttributeToStringTests
{
    [Theory]
    [InlineData(true, "CKA_SENSITIVE = true")]
    [InlineData(false, "CKA_SENSITIVE = false")]
    public void Flag_PrintsItsValue(bool value, string expected)
    {
        using var attribute = new ObjectAttribute(CKA.CKA_SENSITIVE, value);
        Assert.Equal(expected, attribute.ToString());
    }

    [Fact]
    public void TypesAndSizes_PrintTheirValues()
    {
        using var objectClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var keyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
        using var valueLen = new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL);

        Assert.Equal("CKA_CLASS = CKO_SECRET_KEY", objectClass.ToString());
        Assert.Equal("CKA_KEY_TYPE = CKK_AES", keyType.ToString());
        Assert.Equal("CKA_VALUE_LEN = 32", valueLen.ToString());
    }

    [Fact]
    public void UnnamedEnumValue_PrintsAsHex()
    {
        using var keyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, 0x8000_0042UL);
        Assert.Equal("CKA_KEY_TYPE = 0x80000042", keyType.ToString());
    }

    [Fact]
    public void KeyMaterial_IsReportedByLengthOnly()
    {
        byte[] secret = [0xDE, 0xAD, 0xBE, 0xEF];
        using var value = new ObjectAttribute(CKA.CKA_VALUE, secret);

        string text = value.ToString();

        Assert.Equal("CKA_VALUE (4 bytes)", text);
        Assert.DoesNotContain("DEADBEEF", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("222", text); // 0xDE in decimal
    }

    [Fact]
    public void StringValue_IsReportedByLengthOnly()
    {
        using var label = new ObjectAttribute(CKA.CKA_LABEL, "prod-signing-key");

        string text = label.ToString();

        Assert.Equal($"CKA_LABEL ({Encoding.UTF8.GetByteCount("prod-signing-key")} bytes)", text);
        Assert.DoesNotContain("prod-signing-key", text);
    }

    [Fact]
    public void FlagOfTheWrongWidth_FallsBackToLength_WithoutThrowing()
    {
        using var malformed = new ObjectAttribute(CKA.CKA_SIGN, new byte[4]);
        Assert.Equal("CKA_SIGN (4 bytes)", malformed.ToString());
    }

    [Fact]
    public void VendorAttribute_IsNamedByItsCode()
    {
        using var vendor = new ObjectAttribute(0x8000_0123UL, new byte[] { 0x01, 0x02 });
        Assert.Equal("CKA 0x80000123 (2 bytes)", vendor.ToString());
    }

    [Fact]
    public void UnreadableAttribute_SaysSo()
    {
        var unavailable = new CK_ATTRIBUTE
        {
            type = (NativeCULong)(ulong)CKA.CKA_PRIVATE_EXPONENT,
            value = IntPtr.Zero,
            valueLen = NativeCULong.MaxValue,
        };
        using var attribute = new ObjectAttribute(unavailable, ownsValue: false);

        Assert.Equal("CKA_PRIVATE_EXPONENT (unavailable)", attribute.ToString());
    }

    [Fact]
    public void DisposedAttribute_DoesNotThrow()
    {
        var attribute = new ObjectAttribute(CKA.CKA_VALUE, new byte[] { 1, 2, 3 });
        attribute.Dispose();

        Assert.Equal("ObjectAttribute (disposed)", attribute.ToString());
    }
}
