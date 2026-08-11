using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// Hermetic coverage for the object-management surface of <see cref="Pkcs11Session"/>:
/// copy/size, the find pagination loop (<c>FindAllObjects</c> spans more than one
/// <c>C_FindObjects</c> page), the get/set-attribute argument guards, the non-fatal
/// CKR_ATTRIBUTE_SENSITIVE handling in <c>GetAttributeValue</c>, and CKR-&gt;exception mapping.
/// Driven through <see cref="ILowLevelPkcs11Library"/> so the loop and sentinel branches are
/// pinned deterministically rather than relying on a backend's object population.
/// </summary>
public sealed class Pkcs11SessionObjectsTests
{
    private const ulong SessionId = 11;

    // === CopyObject / GetObjectSize =========================================

    private sealed class ObjectFake : FakeLowLevelPkcs11Library
    {
        public CKR CopyRv = CKR.CKR_OK, SizeRv = CKR.CKR_OK, SetAttrRv = CKR.CKR_OK;
        public ulong CopiedId = 0x99;
        public ulong SizeBytes = 128;

        public override CKR C_CopyObject(NativeCULong session, NativeCULong objectId, ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong newObjectId)
        { newObjectId = (NativeCULong)CopiedId; return CopyRv; }
        public override CKR C_GetObjectSize(NativeCULong session, NativeCULong objectId, ref NativeCULong size)
        { size = (NativeCULong)SizeBytes; return SizeRv; }
        public override CKR C_SetAttributeValue(NativeCULong session, NativeCULong objectId, ReadOnlySpan<CK_ATTRIBUTE> template)
            => SetAttrRv;
    }

    private static Pkcs11Session NewSession(FakeLowLevelPkcs11Library fake) => new(fake, SessionId);

    [Fact]
    public void CopyObject_Ok_ReturnsNewHandle()
    {
        var s = NewSession(new ObjectFake { CopiedId = 0x1234 });
        Assert.Equal(0x1234UL, s.CopyObject(new ObjectHandle(1), []).ObjectId);
    }

    [Fact]
    public void CopyObject_Error_Throws()
    {
        var s = NewSession(new ObjectFake { CopyRv = CKR.CKR_OBJECT_HANDLE_INVALID });
        Assert.ThrowsAny<Pkcs11Exception>(() => s.CopyObject(new ObjectHandle(1), []));
    }

    [Fact]
    public void GetObjectSize_Error_Throws()
    {
        var s = NewSession(new ObjectFake { SizeRv = CKR.CKR_INFORMATION_SENSITIVE });
        Assert.ThrowsAny<Pkcs11Exception>(() => s.GetObjectSize(new ObjectHandle(1)));
    }

    // === SetAttributeValue ==================================================

    [Fact]
    public void SetAttributeValue_Ok_DoesNotThrow()
    {
        var s = NewSession(new ObjectFake());
        List<ObjectAttribute> attrs = [new ObjectAttribute(CKA.CKA_LABEL, "x")];
        Assert.Null(Record.Exception(() => s.SetAttributeValue(new ObjectHandle(1), attrs)));
    }

    [Fact]
    public void SetAttributeValue_Error_Throws()
    {
        var s = NewSession(new ObjectFake { SetAttrRv = CKR.CKR_ATTRIBUTE_READ_ONLY });
        List<ObjectAttribute> attrs = [new ObjectAttribute(CKA.CKA_LABEL, "x")];
        Assert.ThrowsAny<Pkcs11Exception>(() => s.SetAttributeValue(new ObjectHandle(1), attrs));
    }

    [Fact]
    public void SetAttributeValue_NullOrEmpty_Throw()
    {
        var s = NewSession(new ObjectFake());
        Assert.Throws<ArgumentNullException>(() => s.SetAttributeValue(new ObjectHandle(1), null!));
        Assert.Throws<ArgumentException>(() => s.SetAttributeValue(new ObjectHandle(1), []));
    }

    // === Find pagination ====================================================

    /// <summary>Returns one page per dequeued count; an empty queue yields a zero-length page.</summary>
    private sealed class FindFake : FakeLowLevelPkcs11Library
    {
        public CKR InitRv = CKR.CKR_OK, FindRv = CKR.CKR_OK, FinalRv = CKR.CKR_OK;
        public readonly Queue<int> Pages = new();
        public int FindCalls { get; private set; }
        public int FinalCalls { get; private set; }

        public override CKR C_FindObjectsInit(NativeCULong session, ReadOnlySpan<CK_ATTRIBUTE> template) => InitRv;
        public override CKR C_FindObjectsFinal(NativeCULong session) { FinalCalls++; return FinalRv; }

        public override CKR C_FindObjects(NativeCULong session, NativeCULong[] objectId, NativeCULong maxObjectCount, ref NativeCULong objectCount)
        {
            FindCalls++;
            int n = Pages.Count > 0 ? Pages.Dequeue() : 0;
            for (int i = 0; i < n; i++)
                objectId[i] = (NativeCULong)(ulong)(FindCalls * 1000 + i);
            objectCount = (NativeCULong)n;
            return FindRv;
        }
    }

    [Fact]
    public void FindObjects_Ok_ReturnsRequestedPage()
    {
        var fake = new FindFake();
        fake.Pages.Enqueue(4);
        var s = NewSession(fake);

        List<ObjectHandle> found = s.FindObjects(5);

        Assert.Equal(4, found.Count);
        Assert.Equal(1000UL, found[0].ObjectId);
    }

    [Fact]
    public void FindAllObjects_PaginatesUntilShortPage_AndFinalizes()
    {
        // First page fills the 256-handle buffer (loop continues); second page is short (loop stops).
        var fake = new FindFake();
        fake.Pages.Enqueue(256);
        fake.Pages.Enqueue(3);
        var s = NewSession(fake);

        List<ObjectHandle> found = s.FindAllObjects([]);

        Assert.Equal(259, found.Count);
        Assert.Equal(2, fake.FindCalls);     // one full page + one short page
        Assert.Equal(1, fake.FinalCalls);    // finalized exactly once
        Assert.Equal(1000UL, found[0].ObjectId);
        Assert.Equal(2002UL, found[^1].ObjectId); // 2nd call -> 2000 + index 2
    }

    [Fact]
    public void FindAllObjects_InitError_Throws()
    {
        var s = NewSession(new FindFake { InitRv = CKR.CKR_OPERATION_ACTIVE });
        Assert.ThrowsAny<Pkcs11Exception>(() => s.FindAllObjects([]));
    }

    [Fact]
    public void FindObjectsInit_Error_Throws()
    {
        var s = NewSession(new FindFake { InitRv = CKR.CKR_ARGUMENTS_BAD });
        Assert.ThrowsAny<Pkcs11Exception>(() => s.FindObjectsInit([]));
    }

    [Fact]
    public void FindObjectsFinal_Error_Throws()
    {
        var s = NewSession(new FindFake { FinalRv = CKR.CKR_OPERATION_NOT_INITIALIZED });
        Assert.ThrowsAny<Pkcs11Exception>(() => s.FindObjectsFinal());
    }

    // === GetAttributeValue ==================================================

    private sealed class AttrFake : FakeLowLevelPkcs11Library
    {
        public CKR Rv = CKR.CKR_OK;
        public bool MarkSensitive; // set the -1 (MaxValue) sentinel so the value cannot be read

        public override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectId, Span<CK_ATTRIBUTE> template)
        {
            if (MarkSensitive)
                for (int i = 0; i < template.Length; i++)
                    template[i].valueLen = NativeCULong.MaxValue;
            return Rv;
        }
    }

    [Fact]
    public void GetAttributeValue_NullOrEmpty_Throw()
    {
        var s = NewSession(new AttrFake());
        Assert.Throws<ArgumentNullException>(() => s.GetAttributeValue(new ObjectHandle(1), (List<CKA>)null!));
        Assert.Throws<ArgumentException>(() => s.GetAttributeValue(new ObjectHandle(1), new List<CKA>()));
    }

    [Fact]
    public void GetAttributeValue_SensitiveSentinel_ReturnsCannotBeRead()
    {
        // CKR_ATTRIBUTE_SENSITIVE is non-fatal: the attribute is reported back with the -1 sentinel
        // rather than throwing.
        var s = NewSession(new AttrFake { Rv = CKR.CKR_ATTRIBUTE_SENSITIVE, MarkSensitive = true });

        using ReadOnlyDisposableList<ObjectAttribute> result = s.GetAttributeValue(new ObjectHandle(1), [CKA.CKA_VALUE]);

        Assert.Single(result);
        Assert.True(result[0].CannotBeRead);
    }

    [Fact]
    public void GetAttributeValue_FatalError_Throws()
    {
        var s = NewSession(new AttrFake { Rv = CKR.CKR_DEVICE_ERROR });
        Assert.ThrowsAny<Pkcs11Exception>(() => s.GetAttributeValue(new ObjectHandle(1), [CKA.CKA_VALUE]));
    }
}
