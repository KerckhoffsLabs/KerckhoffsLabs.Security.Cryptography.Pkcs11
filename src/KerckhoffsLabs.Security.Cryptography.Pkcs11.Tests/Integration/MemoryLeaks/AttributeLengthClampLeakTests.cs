using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.MemoryLeaks;

/// <summary>
/// Refusing an over-long attribute length must free the buffers already handed to the module.
/// </summary>
/// <remarks>
/// <para>
/// The refusal happens after those buffers exist, on a path that had no cleanup at all: ownership
/// passed to the <c>ObjectAttribute</c>s only at the end of the method, so every earlier exit leaked.
/// A guard that threw and leaked would trade an out-of-bounds read for an unbounded leak of buffers
/// that can hold key material, which is a poor trade — hence the assertion.
/// </para>
/// <para>
/// It lives here, in the serialized collection, rather than beside the other clamp tests:
/// <c>UnmanagedMemory.OutstandingAllocationCount</c> is process-global, so read from a parallel test
/// it measures the whole run rather than this one. Written as a unit test it passed locally and on
/// Linux CI, then failed on both Windows legs — and in opposite directions, the x86 count falling by
/// exactly the loop count, which no leak in the code under test could cause.
/// </para>
/// </remarks>
[Collection("MemoryLeaks")]
public sealed class AttributeLengthClampLeakTests
{
    /// <summary>Answers the sizing call honestly, then inflates the length on the fill call.</summary>
    private sealed class LyingLengthFake : FakeLowLevelPkcs11Library
    {
        private int _calls;

        public override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectId, Span<CK_ATTRIBUTE> template)
        {
            _calls++;
            for (int i = 0; i < template.Length; i++)
                template[i].valueLen = (NativeCULong)(_calls == 1 ? 8 : 4096);
            return CKR.CKR_OK;
        }
    }

    private static void ReadAndExpectRefusal()
    {
        using var session = new Pkcs11Session(new LyingLengthFake(), 1);
        Assert.Throws<AttributeValueException>(
            () => session.GetAttributeValue(new ObjectHandle(7), [(ulong)CKA.CKA_VALUE]));
    }

    [Fact]
    public void RefusingAnInflatedLength_FreesTheBuffersItAllocated()
    {
        // Warm up: the first pass through this path allocates one-time state that would read as a leak.
        ReadAndExpectRefusal();

        int before = UnmanagedMemory.OutstandingAllocationCount;

        for (int i = 0; i < 8; i++)
            ReadAndExpectRefusal();

        Assert.Equal(before, UnmanagedMemory.OutstandingAllocationCount);
    }
}
