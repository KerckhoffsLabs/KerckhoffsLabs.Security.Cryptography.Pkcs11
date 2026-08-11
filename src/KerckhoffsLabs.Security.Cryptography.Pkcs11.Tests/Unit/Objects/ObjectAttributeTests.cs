using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Objects;

/// <summary>
/// Comprehensive round-trip tests for every typed ObjectAttribute
/// constructor + the corresponding GetValueAs* reader. Closes the
/// Phase 0a final-review gap on coverage.
///
/// Lifecycle invariants (Dispose, post-dispose access, CannotBeRead)
/// are also covered.
/// </summary>
public sealed class ObjectAttributeTests
{
    // ---- Round-trip per typed constructor -----------------------------------

    [Fact]
    public void RoundTrip_Bool_True()
    {
        using var attr = new ObjectAttribute(CKA.CKA_TOKEN, true);
        Assert.Equal((ulong)CKA.CKA_TOKEN, attr.Type);
        Assert.Equal(1, attr.ValueLength);
        Assert.True(attr.GetValueAsBool());
    }

    [Fact]
    public void RoundTrip_Bool_False()
    {
        using var attr = new ObjectAttribute(CKA.CKA_TOKEN, false);
        Assert.False(attr.GetValueAsBool());
        Assert.Equal(1, attr.ValueLength);
    }

    [Fact]
    public void RoundTrip_Ulong()
    {
        ulong source = 0x123456789ABCDEF0UL;
        using var attr = new ObjectAttribute(CKA.CKA_VALUE_LEN, source);
        // On Windows, NativeCULong is 32-bit — only the low 32 bits are stored
        // and the test platform is Linux-x64 (64-bit storage). Assert what the
        // platform supports.
        ulong roundtripped = attr.GetValueAsUlong();
        if (UnmanagedMemory.NativeULongSize == 4)
            Assert.Equal(source & 0xFFFFFFFFUL, roundtripped);
        else
            Assert.Equal(source, roundtripped);
    }

    [Fact]
    public void RoundTrip_CKO_Enum() // ObjectAttribute(CKA, CKO) overload
    {
        using var attr = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        Assert.Equal((ulong)CKO.CKO_PRIVATE_KEY, attr.GetValueAsUlong());
    }

    [Fact]
    public void RoundTrip_CKK_Enum()
    {
        using var attr = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
        Assert.Equal((ulong)CKK.CKK_AES, attr.GetValueAsUlong());
    }

    [Fact]
    public void RoundTrip_CKC_Enum()
    {
        using var attr = new ObjectAttribute(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509);
        Assert.Equal((ulong)CKC.CKC_X_509, attr.GetValueAsUlong());
    }

    [Fact]
    public void RoundTrip_String_Utf8NoTerminator()
    {
        const string source = "signing-key-α";  // includes non-ASCII to exercise UTF-8
        using var attr = new ObjectAttribute(CKA.CKA_LABEL, source);
        Assert.Equal(source, attr.GetValueAsString());
        // No trailing NUL byte:
        Assert.Equal(Encoding.UTF8.GetByteCount(source), attr.ValueLength);
    }

    [Fact]
    public void RoundTrip_String_Empty()
    {
        using var attr = new ObjectAttribute(CKA.CKA_LABEL, string.Empty);
        Assert.Equal(string.Empty, attr.GetValueAsString());
        Assert.Equal(0, attr.ValueLength);
    }

    [Fact]
    public void RoundTrip_ByteArray()
    {
        byte[] source = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        using var attr = new ObjectAttribute(CKA.CKA_VALUE, source);
        Assert.Equal(source, attr.GetValueAsByteArray());
        Assert.Equal(source.Length, attr.ValueLength);
    }

    [Fact]
    public void RoundTrip_ByteArray_Empty()
    {
        using var attr = new ObjectAttribute(CKA.CKA_VALUE, Array.Empty<byte>());
        Assert.Equal([], attr.GetValueAsByteArray());
        Assert.Equal(0, attr.ValueLength);
    }

    [Fact]
    public void RoundTrip_ReadOnlySpan_MatchesByteArray()
    {
        byte[] source = [1, 2, 3, 4, 5];
        using var fromArray = new ObjectAttribute(CKA.CKA_VALUE, source);
        using var fromSpan = new ObjectAttribute(CKA.CKA_VALUE, (ReadOnlySpan<byte>)source);
        Assert.Equal(fromArray.GetValueAsByteArray(), fromSpan.GetValueAsByteArray());
    }

    [Fact]
    public void RoundTrip_DateTime()
    {
        var source = new DateTime(2026, 12, 31, 0, 0, 0, DateTimeKind.Utc);
        using var attr = new ObjectAttribute(CKA.CKA_START_DATE, source);
        DateTime? roundtripped = attr.GetValueAsDateTime();
        Assert.NotNull(roundtripped);
        // CK_DATE encodes date only; time component is dropped.
        Assert.Equal(source.Date, roundtripped!.Value.Date);
        Assert.Equal(DateTimeKind.Utc, roundtripped!.Value.Kind);
    }

    [Fact]
    public void RoundTrip_ListOfUlong()
    {
        var source = new List<ulong> { 1, 2, 3, 100 };
        using var attr = new ObjectAttribute(CKA.CKA_ALLOWED_MECHANISMS, source);
        ulong[] roundtripped = attr.GetValueAsUlongArray();
        Assert.Equal(source.Count, roundtripped.Length);
        for (int i = 0; i < source.Count; i++)
            Assert.Equal(source[i], roundtripped[i]);
    }

    [Fact]
    public void RoundTrip_ListOfCkm()
    {
        var source = new List<CKM> { CKM.CKM_AES_GCM, CKM.CKM_RSA_PKCS_OAEP };
        using var attr = new ObjectAttribute(CKA.CKA_ALLOWED_MECHANISMS, source);
        CKM[] roundtripped = attr.GetValueAsCkmArray();
        Assert.Equal(source.Count, roundtripped.Length);
        for (int i = 0; i < source.Count; i++)
            Assert.Equal(source[i], roundtripped[i]);
    }

    [Fact]
    public void RoundTrip_NestedAttributeList()
    {
        using var child1 = new ObjectAttribute(CKA.CKA_LABEL, "wrapped");
        using var child2 = new ObjectAttribute(CKA.CKA_TOKEN, true);
        var children = new List<ObjectAttribute> { child1, child2 };

        using var parent = new ObjectAttribute(CKA.CKA_WRAP_TEMPLATE, children);
        ObjectAttribute[] readBack = parent.GetValueAsAttributeArray();

        Assert.Equal(2, readBack.Length);
        // Each readBack[i] wraps a fresh CK_ATTRIBUTE pointing at the
        // SAME unmanaged buffer as parent's child slot. Verify the type
        // field (which lives in the inline struct); reading the children's
        // bytes is unsafe because parent owns the buffer lifetime.
        Assert.Equal((ulong)CKA.CKA_LABEL, readBack[0].Type);
        Assert.Equal((ulong)CKA.CKA_TOKEN, readBack[1].Type);
    }

    // ---- CopyValueTo --------------------------------------------------------

    [Fact]
    public void CopyValueTo_WritesExactBytes()
    {
        byte[] source = [9, 8, 7];
        using var attr = new ObjectAttribute(CKA.CKA_VALUE, source);
        Span<byte> dest = stackalloc byte[8];
        int written = attr.CopyValueTo(dest);
        Assert.Equal(source.Length, written);
        Assert.Equal(source, dest[..written].ToArray());
    }

    [Fact]
    public void CopyValueTo_ThrowsWhenDestinationTooSmall()
    {
        using var attr = new ObjectAttribute(CKA.CKA_VALUE, [1, 2, 3, 4]);
        byte[] tooSmall = new byte[2];
        Assert.Throws<ArgumentException>(() => attr.CopyValueTo(tooSmall));
    }

    // ---- Lifetime / Dispose -------------------------------------------------

    [Fact]
    public void DoubleDisposeIsSafe()
    {
        var attr = new ObjectAttribute(CKA.CKA_VALUE, [1, 2, 3]);
        attr.Dispose();
        Assert.Null(Record.Exception(attr.Dispose)); // must not throw
    }

    [Fact]
    public void PostDisposeAccess_Throws()
    {
        var attr = new ObjectAttribute(CKA.CKA_VALUE, [1, 2, 3]);
        attr.Dispose();
        Assert.Throws<ObjectDisposedException>(() => attr.Type);
        Assert.Throws<ObjectDisposedException>(() => attr.ValueLength);
        Assert.Throws<ObjectDisposedException>(() => attr.GetValueAsByteArray());
        Assert.Throws<ObjectDisposedException>(() => attr.CopyValueTo(new byte[16]));
    }

    // ---- CannotBeRead sentinel (regression for the 32-bit/64-bit Windows
    //      bug caught in Phase 0a final review) ---------------------------

    [Fact]
    public void CannotBeRead_DetectsSentinel()
    {
        // Construct a CK_ATTRIBUTE manually with the sentinel valueLen.
        // The PKCS#11 spec sentinel: valueLen = -1 cast to CK_LONG, i.e.
        // the all-bits-set value of CK_ULONG (= NativeCULong.MaxValue).
        var raw = new CK_ATTRIBUTE
        {
            type = (NativeCULong)(ulong)CKA.CKA_VALUE,
            value = IntPtr.Zero,
            valueLen = NativeCULong.MaxValue,
        };
        using var attr = new ObjectAttribute(raw);

        Assert.True(attr.CannotBeRead);
        Assert.Equal(0, attr.ValueLength); // CannotBeRead short-circuits to 0
    }

    [Fact]
    public void CannotBeRead_ReturnsFalseForNormalAttribute()
    {
        using var attr = new ObjectAttribute(CKA.CKA_VALUE, [1]);
        Assert.False(attr.CannotBeRead);
    }

    [Fact]
    public void GetValueAs_ThrowsOnSensitiveAttribute()
    {
        var raw = new CK_ATTRIBUTE
        {
            type = (NativeCULong)(ulong)CKA.CKA_VALUE,
            value = IntPtr.Zero,
            valueLen = NativeCULong.MaxValue,
        };
        using var attr = new ObjectAttribute(raw);

        Assert.Throws<AttributeValueException>(() => attr.GetValueAsBool());
        Assert.Throws<AttributeValueException>(() => attr.GetValueAsUlong());
        Assert.Throws<AttributeValueException>(() => attr.GetValueAsString());
        Assert.Throws<AttributeValueException>(() => attr.GetValueAsByteArray());
        Assert.Throws<AttributeValueException>(() => attr.CopyValueTo(new byte[16]));
        Assert.Throws<AttributeValueException>(() => attr.GetValueAsDateTime());
    }

    // ---- ulong-typed constructor for raw vendor attribute IDs -------------

    [Fact]
    public void RawUlongTypeCtor_PreservesVendorAttributeId()
    {
        const ulong vendorAttrId = 0x80000042; // CKA_VENDOR_DEFINED + 0x42
        using var attr = new ObjectAttribute(vendorAttrId, [0xAA]);
        Assert.Equal(vendorAttrId, attr.Type);
        Assert.Single(attr.GetValueAsByteArray(), (byte)0xAA);
    }

    /// <summary>
    /// The views handed back by <c>GetValueAsAttributeArray</c> point at buffers the nested
    /// children own. They must not free on disposal, or a stray <c>using</c> over the read-back
    /// array would release memory the original children still describe — and, now that
    /// ObjectAttribute has a finalizer, would do so unprompted at the next GC.
    /// </summary>
    [Fact]
    public void GetValueAsAttributeArray_ReturnsNonOwningViews()
    {
        using var child = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var parent = new ObjectAttribute(CKA.CKA_WRAP_TEMPLATE, [child]);

        foreach (ObjectAttribute view in parent.GetValueAsAttributeArray())
            view.Dispose();

        // The child's buffer survived the views being disposed: still readable, still its value.
        Assert.True(child.GetValueAsBool());
    }

    /// <summary>
    /// Dispose and the finalizer can both reach the release path. UnmanagedMemory.Free throws on a
    /// second free, and that throw on the finalizer thread would tear the process down, so the
    /// claim is atomic and a repeated Dispose must be silent.
    /// </summary>
    [Fact]
    public void Dispose_IsIdempotent()
    {
        var attr = new ObjectAttribute(CKA.CKA_VALUE, new byte[] { 1, 2, 3 });

        attr.Dispose();

        Assert.Null(Record.Exception(attr.Dispose));
    }

    /// <summary>
    /// A nested template copies each child's CK_ATTRIBUTE struct verbatim, so a disposed child
    /// would be copied as {type, NULL, 0} — an attribute that is present but empty. In a
    /// CKA_WRAP_TEMPLATE that is a different filter than the caller wrote, and it would reach the
    /// token silently. Refuse instead.
    /// </summary>
    [Fact]
    public void NestedAttributeList_WithADisposedChild_Throws()
    {
        var child = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        child.Dispose();

        Assert.Throws<ObjectDisposedException>(
            () => new ObjectAttribute(CKA.CKA_WRAP_TEMPLATE, [child]));
    }
}
