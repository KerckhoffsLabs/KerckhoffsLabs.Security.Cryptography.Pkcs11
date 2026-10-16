using System.Runtime.InteropServices;
using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// How <see cref="Pkcs11Session.FindKeys"/> and <see cref="Pkcs11Session.FindObjects"/> read a found
/// object's class, key type, label and id: one <c>C_GetAttributeValue</c> per object when the token
/// answers cleanly, and the generic two-call read, with the same result, whenever it does not.
/// </summary>
/// <remarks>
/// A round trip per object is the cost a network HSM charges for every key a search returns, so the
/// call counts here are the contract, not an implementation detail.
/// </remarks>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11SessionHydrationTests
{
    private static readonly byte[] SecretKeyClass = ULong((ulong)CKO.CKO_SECRET_KEY);
    private static readonly byte[] DataClass = ULong((ulong)CKO.CKO_DATA);
    private static readonly byte[] AesKeyType = ULong((ulong)CKK.CKK_AES);

    [Fact]
    public void FindKeys_ReadsEachKeyInOneCall()
    {
        using var module = new IdentityModule();
        for (int i = 0; i < 3; i++)
            module.Add(SecretKey($"key-{i}", [(byte)i, 0xAA]));
        using var session = module.OpenSession();

        using var keys = session.FindKeys();

        Assert.Equal(3, keys.Count);
        for (int i = 0; i < 3; i++)
        {
            Assert.Equal($"key-{i}", keys[i].Label);
            Assert.Equal([(byte)i, 0xAA], keys[i].Id.ToArray());
            Assert.Equal(CKK.CKK_AES, keys[i].KeyType);
        }
        Assert.Equal(3, module.CallCount("C_GetAttributeValue"));
    }

    [Fact]
    public void FindObjects_ReadsEachObjectInOneCall()
    {
        using var module = new IdentityModule();
        module.Add(SecretKey("first", [0x01]));
        module.Add(SecretKey("second", [0x02]));
        using var session = module.OpenSession();

        using var objects = session.FindObjects();

        Assert.Equal(["first", "second"], objects.Select(o => o.Label));
        Assert.All(objects, o => Assert.Equal(CKO.CKO_SECRET_KEY, o.ObjectClass));
        Assert.Equal(2, module.CallCount("C_GetAttributeValue"));
    }

    // Same decoding as the generic reader: trailing NUL padding trimmed, an empty label is "", an
    // empty id is empty.
    [Theory]
    [InlineData("padded\0\0\0", "padded")]
    [InlineData("", "")]
    [InlineData("ünïcödé", "ünïcödé")]
    public void OneCallRead_DecodesTheLabelLikeTheGenericReader(string stored, string expected)
    {
        using var module = new IdentityModule();
        module.Add(SecretKey(stored, []));
        using var session = module.OpenSession();

        using var keys = session.FindKeys();

        Assert.Equal(expected, Assert.Single(keys).Label);
        Assert.True(keys[0].Id.IsEmpty);
        Assert.Equal(1, module.CallCount("C_GetAttributeValue"));
    }

    // Each case makes the one-call read unusable. The result must be what the generic reader gives,
    // and nothing may throw that did not throw before: one failed attempt, then its two calls.
    [Theory]
    [InlineData(Quirk.LongLabel)]
    [InlineData(Quirk.ReportsOkForTooSmallBuffer)]
    [InlineData(Quirk.ReportsUnavailableWithOk)]
    public void UnusableOneCallRead_FallsBackToTheGenericReader(Quirk quirk)
    {
        string label = quirk == Quirk.ReportsUnavailableWithOk ? "short" : new string('L', ObjectIdentityReader.LabelCapacity + 72);
        using var module = new IdentityModule { Quirk = quirk };
        module.Add(SecretKey(label, [0x07]));
        using var session = module.OpenSession();

        using var keys = session.FindKeys();

        Pkcs11Key key = Assert.Single(keys);
        Assert.Equal(label, key.Label);
        Assert.Equal([0x07], key.Id.ToArray());
        Assert.Equal(CKK.CKK_AES, key.KeyType);
        Assert.Equal(3, module.CallCount("C_GetAttributeValue"));
    }

    // A data object has no CKA_ID, so the token answers CKR_ATTRIBUTE_TYPE_INVALID and the generic
    // reader reports the id as empty, as before.
    [Fact]
    public void ObjectWithoutAnId_FallsBackAndReadsAnEmptyId()
    {
        using var module = new IdentityModule();
        module.Add(new()
        {
            [CKA.CKA_CLASS] = DataClass,
            [CKA.CKA_LABEL] = "data"u8.ToArray(),
        });
        using var session = module.OpenSession();

        using var objects = session.FindObjects();

        Pkcs11Object obj = Assert.Single(objects);
        Assert.Equal(CKO.CKO_DATA, obj.ObjectClass);
        Assert.Equal("data", obj.Label);
        Assert.True(obj.Id.IsEmpty);
        Assert.Equal(3, module.CallCount("C_GetAttributeValue"));
    }

    // A CK_ULONG of the wrong width is not trusted on the one-call path; the generic reader then
    // refuses it exactly as it did before.
    [Fact]
    public void ClassOfTheWrongWidth_IsRefusedByTheGenericReader()
    {
        using var module = new IdentityModule();
        module.Add(new()
        {
            [CKA.CKA_CLASS] = [0x04, 0x00],
            [CKA.CKA_KEY_TYPE] = AesKeyType,
            [CKA.CKA_LABEL] = "k"u8.ToArray(),
            [CKA.CKA_ID] = [0x01],
        });
        using var session = module.OpenSession();

        Assert.Throws<Pkcs11AttributeException>(() => session.FindKeys());
        Assert.Equal(3, module.CallCount("C_GetAttributeValue"));
    }

    // The value is read from the buffer the session handed out, never from a pointer the module
    // writes back into the template.
    [Fact]
    public void RedirectedPointer_IsIgnored()
    {
        using var module = new IdentityModule { Quirk = Quirk.RedirectsLabelPointer };
        module.Add(SecretKey("real", [0x01]));
        using var session = module.OpenSession();

        using var keys = session.FindKeys();

        Assert.Equal("real", Assert.Single(keys).Label);
        Assert.Equal(1, module.CallCount("C_GetAttributeValue"));
    }

    public enum Quirk
    {
        None,

        /// <summary>The label does not fit the one-call buffer: <c>CKR_BUFFER_TOO_SMALL</c>, as the spec says.</summary>
        LongLabel,

        /// <summary>A buffer too small for the label gets <c>CKR_OK</c> and the full length, and nothing written.</summary>
        ReportsOkForTooSmallBuffer,

        /// <summary>The label is reported as <c>CK_UNAVAILABLE_INFORMATION</c> under <c>CKR_OK</c>.</summary>
        ReportsUnavailableWithOk,

        /// <summary>The module writes the real label and then points the template entry at a decoy.</summary>
        RedirectsLabelPointer,
    }

    private static Dictionary<CKA, byte[]> SecretKey(string label, byte[] id) => new()
    {
        [CKA.CKA_CLASS] = SecretKeyClass,
        [CKA.CKA_KEY_TYPE] = AesKeyType,
        [CKA.CKA_LABEL] = Encoding.UTF8.GetBytes(label),
        [CKA.CKA_ID] = id,
    };

    private static byte[] ULong(ulong value)
    {
        byte[] bytes = new byte[UnmanagedMemory.NativeULongSize];
        MemoryMarshal.Write(bytes, (NativeCULong)value);
        return bytes;
    }

    /// <summary>
    /// A token holding a few objects: every search returns all of them, in order, and
    /// <c>C_GetAttributeValue</c> answers per the spec unless <see cref="Quirk"/> says otherwise.
    /// </summary>
    private sealed class IdentityModule : FakeModule
    {
        // Pinned for the process lifetime, so its address is a stable stand-in for module-owned memory.
        private static readonly byte[] Decoy = CreateDecoy();
        private readonly List<Dictionary<CKA, byte[]>> _objects = [];
        private int _next;

        public Quirk Quirk { get; init; }

        protected override bool ReleasedByFinalize => true;

        public void Add(Dictionary<CKA, byte[]> attributes) => _objects.Add(attributes);

        public SessionScope OpenSession()
        {
            Pkcs11Library library = Load();
            LowLevelPkcs11Library lowLevel = library.LowLevelLibrary!;
            var core = new Pkcs11SessionCore(lowLevel, slotId: default, sessionId: 1);
            return new SessionScope(new Pkcs11Session(library, new Pkcs11Slot(lowLevel, slotId: 1), core), library);
        }

        protected override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;

        protected override CKR C_FindObjectsInit(NativeCULong session, CK_ATTRIBUTE[] template)
        {
            _next = 0;
            return CKR.CKR_OK;
        }

        protected override CKR C_FindObjects(NativeCULong session, Span<NativeCULong> objects, ref NativeCULong count)
        {
            int n = 0;
            while (n < objects.Length && _next < _objects.Count)
                objects[n++] = (NativeCULong)(ulong)(++_next);
            count = (NativeCULong)(ulong)n;
            return CKR.CKR_OK;
        }

        protected override CKR C_FindObjectsFinal(NativeCULong session) => CKR.CKR_OK;

        protected override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectHandle, Span<CK_ATTRIBUTE> template)
        {
            Dictionary<CKA, byte[]> obj = _objects[(int)(ulong)objectHandle - 1];
            CKR rv = CKR.CKR_OK;
            for (int i = 0; i < template.Length; i++)
            {
                ref CK_ATTRIBUTE attribute = ref template[i];
                var type = (CKA)(ulong)attribute.type;
                if (!obj.TryGetValue(type, out byte[]? value))
                {
                    attribute.valueLen = NativeCULong.MaxValue;
                    rv = CKR.CKR_ATTRIBUTE_TYPE_INVALID;
                    continue;
                }

                bool oneCallLabel = type == CKA.CKA_LABEL && attribute.value != IntPtr.Zero
                    && (ulong)attribute.valueLen == ObjectIdentityReader.LabelCapacity;
                if (oneCallLabel && Quirk == Quirk.ReportsUnavailableWithOk)
                {
                    attribute.valueLen = NativeCULong.MaxValue;
                    continue;
                }
                if (oneCallLabel && Quirk == Quirk.ReportsOkForTooSmallBuffer && value.Length > ObjectIdentityReader.LabelCapacity)
                {
                    attribute.valueLen = (NativeCULong)(ulong)value.Length;
                    continue;
                }

                CKR answer = AnswerAttribute(ref attribute, value);
                if (answer != CKR.CKR_OK)
                    rv = answer;
                else if (oneCallLabel && Quirk == Quirk.RedirectsLabelPointer)
                    attribute.value = Marshal.UnsafeAddrOfPinnedArrayElement(Decoy, 0);
            }
            return rv;
        }

        private static byte[] CreateDecoy()
        {
            byte[] decoy = GC.AllocateArray<byte>(5, pinned: true);
            "decoy"u8.CopyTo(decoy);
            return decoy;
        }
    }

    /// <summary>The session and the library behind it, disposed together, session first.</summary>
    private sealed class SessionScope(Pkcs11Session session, Pkcs11Library library) : IDisposable
    {
        // The module returns every object whatever the filter, so an empty one does.
        public ReadOnlyDisposableList<Pkcs11Key> FindKeys()
        {
            using ObjectTemplate filter = ObjectTemplate.Empty().Build();
            return session.FindKeys(filter);
        }

        public ReadOnlyDisposableList<Pkcs11Object> FindObjects()
        {
            using ObjectTemplate filter = ObjectTemplate.Empty().Build();
            return session.FindObjects(filter);
        }

        public void Dispose()
        {
            session.Dispose();
            library.Dispose();
        }
    }
}
