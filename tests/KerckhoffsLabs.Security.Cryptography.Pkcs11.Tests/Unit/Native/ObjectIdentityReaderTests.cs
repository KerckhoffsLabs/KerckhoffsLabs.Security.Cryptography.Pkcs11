using KerckhoffsLabs.Runtime.InteropServices;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// <see cref="ObjectIdentityReader"/> against a module that writes the template as each test says: an identity is
/// read only when every attribute came back at a length its buffer can hold, and a session object's mark keeps
/// what the module did report when the rest is missing.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class ObjectIdentityReaderTests
{
    private static readonly NativeCULong Session = (NativeCULong)1UL;
    private static readonly NativeCULong Object = (NativeCULong)7UL;
    private static readonly byte[] KeyId = [0x01, 0x02];

    // === TryRead ===========================================================

    [Fact]
    public void TryRead_EveryAttributeReported_GivesTheIdentity()
    {
        (bool read, ObjectIdentity identity) = TryRead(withKeyType: true, (_, template) => WriteIdentity(template));

        Assert.True(read);
        Assert.Equal((CKO.CKO_SECRET_KEY, CKK.CKK_AES, "key", true), (identity.ObjectClass, identity.KeyType, identity.Label, identity.IsPrivate));
        Assert.Equal(KeyId, identity.Id);
    }

    // A key type the module could not give (CK_UNAVAILABLE_INFORMATION, under CKR_OK) leaves no identity, rather
    // than one with a key type of 0, CKK_RSA.
    [Fact]
    public void TryRead_KeyTypeNotReported_ReadsNoIdentity()
    {
        (bool read, _) = TryRead(withKeyType: true, (_, template) =>
        {
            WriteIdentity(template);
            Attributes.Unavailable(ref Attributes.Find(template, CKA.CKA_KEY_TYPE));
            return CKR.CKR_OK;
        });

        Assert.False(read);
    }

    // Likewise CKA_PRIVATE: a missing one is not read as false (a public object).
    [Fact]
    public void TryRead_PrivateNotReported_ReadsNoIdentity()
    {
        (bool read, _) = TryRead(withKeyType: false, (_, template) =>
        {
            WriteIdentity(template);
            Attributes.Unavailable(ref Attributes.Find(template, CKA.CKA_PRIVATE));
            return CKR.CKR_OK;
        });

        Assert.False(read);
    }

    // === ReadSessionObjectMark ============================================

    [Fact]
    public void ReadSessionObjectMark_EveryAttributeReported_GivesTheMark()
    {
        SessionObjectMark mark = ReadMark((_, template) => WriteMark(template, Encoding.UTF8.GetBytes("lent")));

        Assert.Equal(new SessionObjectMark(false, CKO.CKO_DATA, Encoding.UTF8.GetBytes("lent")), mark, MarkComparer.Instance);
    }

    // A code that does not answer per attribute: nothing is known about the object.
    [Fact]
    public void ReadSessionObjectMark_OtherReturnCode_GivesAnEmptyMark()
    {
        SessionObjectMark mark = ReadMark((_, template) =>
        {
            WriteMark(template, [0x41]);
            return CKR.CKR_DEVICE_ERROR;
        });

        Assert.Equal(default, mark, MarkComparer.Instance);
    }

    // CKR_ATTRIBUTE_SENSITIVE with nothing usable: each part is unknown, and the label, reported as
    // CK_UNAVAILABLE_INFORMATION without CKR_BUFFER_TOO_SMALL, is not read again.
    [Fact]
    public void ReadSessionObjectMark_NothingReported_GivesUnknownParts_WithoutReadingTheLabelAgain()
    {
        using var module = new TemplateAnswerModule((_, template) =>
        {
            foreach (ref CK_ATTRIBUTE attribute in template)
                Attributes.Unavailable(ref attribute);
            return CKR.CKR_ATTRIBUTE_SENSITIVE;
        });

        SessionObjectMark mark = module.With(library => ObjectIdentityReader.ReadSessionObjectMark(library, Session, Object));

        Assert.Equal(new SessionObjectMark(null, null, null), mark, MarkComparer.Instance);
        Assert.Equal(1, module.Calls["C_GetAttributeValue"]);
    }

    // A label longer than the stack buffer answers CKR_BUFFER_TOO_SMALL, and is read again on its own.
    [Fact]
    public void ReadSessionObjectMark_LongLabel_IsReadAgainOnItsOwn()
    {
        byte[] label = LongLabel();
        SessionObjectMark mark = ReadMark((call, template) =>
            call == 0 ? WriteMark(template, label) : Attributes.Bytes(ref template[0], label));

        Assert.Equal(label, mark.Label);
    }

    public static TheoryData<string> LongLabelFailures => ["query fails", "too long", "read fails", "length changes"];

    // The second read of a long label is given up, leaving it unknown, when the length query fails or reports more
    // than LongLabelLimit, or the read fails or comes back at another length than the query gave.
    [Theory]
    [MemberData(nameof(LongLabelFailures))]
    public void ReadSessionObjectMark_LongLabelThatCannotBeReadAgain_IsUnknown(string failure)
    {
        byte[] label = LongLabel();
        SessionObjectMark mark = ReadMark((call, template) => call switch
        {
            0 => WriteMark(template, label),
            1 => failure switch
            {
                "query fails" => CKR.CKR_DEVICE_ERROR,
                "too long" => Length(template, ObjectIdentityReader.LongLabelLimit + 1),
                _ => Attributes.Bytes(ref template[0], label),
            },
            _ => failure switch
            {
                "read fails" => CKR.CKR_DEVICE_ERROR,
                _ => Length(template, label.Length - 1),
            },
        });

        Assert.Null(mark.Label);
        Assert.Equal(CKO.CKO_DATA, mark.ObjectClass);
    }

    // === SessionObjectMark.Matches ========================================

    public static TheoryData<byte[]?, byte[]?, bool> Labels => new()
    {
        { null, null, true },
        { null, [0x41], false },
        { [0x41], null, false },
        { [0x41], [0x41], true },
        { [0x41], [0x42], false },
    };

    // The class and the label decide; a label known on one side only is not a match.
    [Theory]
    [MemberData(nameof(Labels))]
    public void Matches_ComparesTheLabels(byte[]? now, byte[]? recorded, bool matches)
        => Assert.Equal(matches, new SessionObjectMark(false, CKO.CKO_DATA, now).Matches(new SessionObjectMark(false, CKO.CKO_DATA, recorded)));

    [Fact]
    public void Matches_AnotherClass_DoesNotMatch()
        => Assert.False(new SessionObjectMark(false, CKO.CKO_DATA, null).Matches(new SessionObjectMark(false, CKO.CKO_SECRET_KEY, null)));

    // === Helpers ===========================================================

    private static (bool Read, ObjectIdentity Identity) TryRead(bool withKeyType, TemplateAnswer answer)
    {
        using var module = new TemplateAnswerModule(answer);
        ObjectIdentity identity = default;
        bool read = module.With(library => ObjectIdentityReader.TryRead(library, Session, Object, withKeyType, out identity));
        return (read, identity);
    }

    private static SessionObjectMark ReadMark(TemplateAnswer answer)
    {
        using var module = new TemplateAnswerModule(answer);
        return module.With(library => ObjectIdentityReader.ReadSessionObjectMark(library, Session, Object));
    }

    private static CKR WriteIdentity(Span<CK_ATTRIBUTE> template)
    {
        foreach (ref CK_ATTRIBUTE attribute in template)
        {
            switch ((CKA)(ulong)attribute.type)
            {
                case CKA.CKA_CLASS: Attributes.Ulong(ref attribute, (ulong)CKO.CKO_SECRET_KEY); break;
                case CKA.CKA_KEY_TYPE: Attributes.Ulong(ref attribute, (ulong)CKK.CKK_AES); break;
                case CKA.CKA_LABEL: Attributes.Bytes(ref attribute, "key"u8); break;
                case CKA.CKA_ID: Attributes.Bytes(ref attribute, KeyId); break;
                case CKA.CKA_PRIVATE: Attributes.Bool(ref attribute, true); break;
            }
        }
        return CKR.CKR_OK;
    }

    // CKA_TOKEN false, CKA_CLASS CKO_DATA, and the label: CKR_BUFFER_TOO_SMALL when it does not fit.
    private static CKR WriteMark(Span<CK_ATTRIBUTE> template, byte[] label)
    {
        Attributes.Bool(ref Attributes.Find(template, CKA.CKA_TOKEN), false);
        Attributes.Ulong(ref Attributes.Find(template, CKA.CKA_CLASS), (ulong)CKO.CKO_DATA);
        return Attributes.Bytes(ref Attributes.Find(template, CKA.CKA_LABEL), label);
    }

    // Answers with a length alone, whatever the buffer.
    private static CKR Length(Span<CK_ATTRIBUTE> template, int length)
    {
        template[0].valueLen = (NativeCULong)(ulong)length;
        return CKR.CKR_OK;
    }

    private static byte[] LongLabel() => [.. Enumerable.Repeat((byte)'L', ObjectIdentityReader.LabelCapacity + 72)];

    // The mark is a record over byte arrays, so its own equality compares the labels by reference.
    private sealed class MarkComparer : IEqualityComparer<SessionObjectMark>
    {
        public static readonly MarkComparer Instance = new();

        public bool Equals(SessionObjectMark x, SessionObjectMark y)
            => x.IsToken == y.IsToken && x.ObjectClass == y.ObjectClass
                && (x.Label is null ? y.Label is null : y.Label is not null && x.Label.AsSpan().SequenceEqual(y.Label));

        public int GetHashCode(SessionObjectMark mark) => HashCode.Combine(mark.IsToken, mark.ObjectClass);
    }
}
