using System.Runtime.InteropServices;
using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.MemoryLeaks;

/// <summary>
/// Reading back an attribute array (<c>CKA_WRAP_TEMPLATE</c>) takes three <c>C_GetAttributeValue</c>
/// calls and one buffer per member. These tests drive that protocol through a module, the real
/// wrappers included, and pin what the read leaves behind: every buffer either owned by the returned
/// attribute or freed, and nothing the module wrote able to choose what is read or freed.
/// </summary>
/// <remarks>
/// In the serialized MemoryLeaks collection: <c>UnmanagedMemory.OutstandingAllocationCount</c> is
/// process-global, so it only measures this test when nothing else runs alongside.
/// </remarks>
[Collection("MemoryLeaks")]
public sealed class NestedAttributeReadBackTests
{
    private const int Rounds = 8;

    [Fact]
    public void ReadBack_ReturnsTheMembersValues()
    {
        using var module = new WrapTemplateModule();
        using var session = OpenSession(module);

        using ReadOnlyDisposableList<ObjectAttribute> read = session.GetAttributeValue(new ObjectHandle(1), [(ulong)CKA.CKA_WRAP_TEMPLATE]);

        ObjectAttribute[] members = read[0].GetValueAsAttributeArray();
        Assert.Equal((ulong)CKO.CKO_SECRET_KEY, members[0].GetValueAsUlong());
        Assert.Equal("inner", members[1].GetValueAsString());
        Assert.Equal(3, module.CallCount("C_GetAttributeValue"));
    }

    [Fact]
    public void ReadBack_LeavesNoBufferBehind()
    {
        using var module = new WrapTemplateModule();
        using var session = OpenSession(module);
        ReadAndDispose(session); // warm up one-time state

        int before = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < Rounds; i++)
            ReadAndDispose(session);

        // Used to leak one buffer per member per read: the members' buffers had no owner.
        Assert.Equal(before, UnmanagedMemory.OutstandingAllocationCount);
    }

    [Fact]
    public void ReadBack_AttributeOwnsOneBlock()
    {
        using var module = new WrapTemplateModule();
        using var session = OpenSession(module);
        ReadAndDispose(session);

        int before = UnmanagedMemory.OutstandingAllocationCount;
        using ReadOnlyDisposableList<ObjectAttribute> read = session.GetAttributeValue(new ObjectHandle(1), [(ulong)CKA.CKA_WRAP_TEMPLATE]);

        Assert.Equal(before + 1, UnmanagedMemory.OutstandingAllocationCount);
    }

    [Theory]
    [InlineData(Lie.InflateTopLevelOnThirdCall)]
    [InlineData(Lie.InflateMemberOnThirdCall)]
    public void InflatedLengthOnTheThirdCall_IsRefused_AndLeavesNothingBehind(Lie lie)
    {
        using var module = new WrapTemplateModule { Lie = lie };
        using var session = OpenSession(module);
        Assert.Throws<Pkcs11AttributeException>(() => ReadAndDispose(session));

        int before = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < Rounds; i++)
            Assert.Throws<Pkcs11AttributeException>(() => ReadAndDispose(session));

        Assert.Equal(before, UnmanagedMemory.OutstandingAllocationCount);
    }

    /// <summary>
    /// A module that hands back its own pointer must not get it read or freed: freeing memory that
    /// was never allocated here throws, and on the finalizer thread that ends the process.
    /// </summary>
    [Fact]
    public void RedirectedPointer_IsIgnored_AndTheReadComesFromTheSessionsBuffer()
    {
        using var module = new WrapTemplateModule { Lie = Lie.RedirectLabelOnSecondCall };
        using var session = OpenSession(module);

        using (ReadOnlyDisposableList<ObjectAttribute> read = session.GetAttributeValue(new ObjectHandle(1), [(ulong)CKA.CKA_LABEL]))
        {
            // The module wrote the real label into the buffer it was given, and its decoy elsewhere.
            Assert.Equal("outer", read[0].GetValueAsString());
        }

        int before = UnmanagedMemory.OutstandingAllocationCount;
        for (int i = 0; i < Rounds; i++)
            session.GetAttributeValue(new ObjectHandle(1), [(ulong)CKA.CKA_LABEL]).Dispose();
        Assert.Equal(before, UnmanagedMemory.OutstandingAllocationCount);
    }

    private static Pkcs11Session OpenSession(WrapTemplateModule module)
        => new(module.LoadLowLevel(), (ulong)module.OpenSession());

    private static void ReadAndDispose(Pkcs11Session session)
        => session.GetAttributeValue(new ObjectHandle(1), [(ulong)CKA.CKA_WRAP_TEMPLATE]).Dispose();

    public enum Lie
    {
        None,
        InflateTopLevelOnThirdCall,
        InflateMemberOnThirdCall,
        RedirectLabelOnSecondCall,
    }

    /// <summary>
    /// One object: <c>CKA_LABEL</c> = "outer", and a <c>CKA_WRAP_TEMPLATE</c> of two members,
    /// <c>CKA_CLASS</c> = <c>CKO_SECRET_KEY</c> and <c>CKA_LABEL</c> = "inner", answered the way a
    /// module answers the three-call protocol: lengths, then the member headers, then their values.
    /// </summary>
    private sealed class WrapTemplateModule : FakeModule
    {
        // Pinned for the process lifetime, so its address is a stable stand-in for module-owned memory.
        private static readonly byte[] Decoy = CreateDecoy();
        private int _call;

        public Lie Lie { get; init; }

        // Each read of a wrap template is three calls (a label-only read is two), so the position
        // within the current read is the call count modulo the read's length.
        private bool ThirdCall => _call % 3 == 0;
        private bool SecondCall => _call % 2 == 0;

        public NativeCULong OpenSession() => NewSessionHandle();

        protected override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;

        protected override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectHandle, Span<CK_ATTRIBUTE> template)
        {
            _call++;
            int stride = UnmanagedMemory.SizeOf<CK_ATTRIBUTE>();
            for (int i = 0; i < template.Length; i++)
            {
                ref CK_ATTRIBUTE attribute = ref template[i];
                switch ((CKA)(ulong)attribute.type)
                {
                    case CKA.CKA_LABEL:
                        AnswerAttribute(ref attribute, "outer"u8);
                        if (Lie == Lie.RedirectLabelOnSecondCall && SecondCall)
                        {
                            attribute.value = Marshal.UnsafeAddrOfPinnedArrayElement(Decoy, 0);
                        }
                        break;

                    case CKA.CKA_WRAP_TEMPLATE:
                        if (attribute.value != IntPtr.Zero)
                            AnswerMembers(attribute.value, stride);
                        attribute.valueLen = (NativeCULong)(ulong)(2 * stride);
                        if (Lie == Lie.InflateTopLevelOnThirdCall && ThirdCall)
                            attribute.valueLen = (NativeCULong)(ulong)(4 * stride);
                        break;

                    default:
                        attribute.valueLen = NativeCULong.MaxValue;
                        break;
                }
            }
            return CKR.CKR_OK;
        }

        // Fills the member headers in the caller's array block, and their values once the caller has
        // given each member a buffer.
        private void AnswerMembers(IntPtr array, int stride)
        {
            byte[] secretKeyClass = new byte[UnmanagedMemory.NativeULongSize];
            MemoryMarshal.Write(secretKeyClass, (NativeCULong)(ulong)CKO.CKO_SECRET_KEY);
            (CKA Type, byte[] Value)[] members = [(CKA.CKA_CLASS, secretKeyClass), (CKA.CKA_LABEL, Encoding.ASCII.GetBytes("inner"))];

            for (int j = 0; j < members.Length; j++)
            {
                IntPtr slot = IntPtr.Add(array, j * stride);
                CK_ATTRIBUTE member = UnmanagedMemory.Read<CK_ATTRIBUTE>(slot);
                member.type = (NativeCULong)(ulong)members[j].Type;
                AnswerAttribute(ref member, members[j].Value);
                if (Lie == Lie.InflateMemberOnThirdCall && ThirdCall && j == 1)
                    member.valueLen = (NativeCULong)4096UL;
                UnmanagedMemory.Write(slot, in member);
            }
        }

        private static byte[] CreateDecoy()
        {
            byte[] decoy = GC.AllocateArray<byte>(5, pinned: true);
            "decoy"u8.CopyTo(decoy);
            return decoy;
        }
    }
}
