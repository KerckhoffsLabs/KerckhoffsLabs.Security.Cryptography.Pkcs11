using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// <c>C_GetAttributeValue</c> is a two-call idiom: the first call reports how long a value is, the
/// library allocates that much, and the second call fills it. The length that comes back from the
/// second call is what every reader on <c>ObjectAttribute</c> then uses to size its read.
/// </summary>
/// <remarks>
/// <para>
/// Nothing in PKCS#11 obliges a module to report the same length twice. A module that reports a larger
/// one the second time — through a bug, or deliberately — makes the library read past the end of a
/// buffer it sized from the module's own earlier answer, handing whatever unmanaged memory follows it
/// back to the caller as attribute data. The module needs no memory-safety bug of its own to do this;
/// it only has to answer a question inconsistently, and it returns <c>CKR_OK</c> throughout.
/// </para>
/// <para>
/// These tests drive that behaviour through the <c>ILowLevelPkcs11Library</c> seam, since no real
/// module will misbehave on request. That refusing does not leak the buffers already handed out — the
/// property that makes this guard safe to add to a path which had no cleanup before it — is asserted
/// by <c>AttributeLengthClampLeakTests</c>, which has to be serialized and so lives apart.
/// </para>
/// </remarks>
public sealed class AttributeLengthClampTests
{
    private const ulong ObjectId = 7;

    /// <summary>Answers the sizing call honestly, then inflates the length on the fill call.</summary>
    private sealed class LyingLengthFake(int honestLen, int inflatedLen) : FakeLowLevelPkcs11Library
    {
        private int _calls;

        public override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectId, Span<CK_ATTRIBUTE> template)
        {
            _calls++;
            for (int i = 0; i < template.Length; i++)
            {
                // First call: a plausible size. Second: the same buffer, described as far bigger.
                template[i].valueLen = (NativeCULong)(_calls == 1 ? honestLen : inflatedLen);
            }
            return CKR.CKR_OK;
        }
    }

    /// <summary>Consistent and well-behaved — the control for the tests below.</summary>
    private sealed class HonestFake(int len) : FakeLowLevelPkcs11Library
    {
        public override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectId, Span<CK_ATTRIBUTE> template)
        {
            for (int i = 0; i < template.Length; i++)
                template[i].valueLen = (NativeCULong)len;
            return CKR.CKR_OK;
        }
    }

    private static ReadOnlyDisposableList<ObjectAttribute> Read(FakeLowLevelPkcs11Library fake)
    {
        using var session = new Pkcs11Session(fake, 1);
        return session.GetAttributeValue(new ObjectHandle(ObjectId), [(ulong)CKA.CKA_VALUE]);
    }

    [Fact]
    public void InflatedLengthOnTheFillCall_IsRefused()
    {
        var ex = Assert.Throws<AttributeValueException>(
            () => Read(new LyingLengthFake(honestLen: 8, inflatedLen: 4096)));

        Assert.Equal(CKA.CKA_VALUE, ex.Attribute);
        // The message must name both numbers: a caller's next move is to identify the module, and
        // "could not be read" would send them looking at their own template instead.
        Assert.Contains("4096", ex.Message, StringComparison.Ordinal);
        Assert.Contains("8-byte", ex.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The guard must not fire on the ordinary case, including the one a module is entitled to: a
    /// second call reporting *fewer* bytes than the first.
    /// </summary>
    [Theory]
    [InlineData(32, 32)] // same length twice — the common case
    [InlineData(32, 8)]  // shrank; legal, and the value is genuinely 8 bytes
    [InlineData(32, 0)]  // shrank to nothing
    public void LengthsWithinTheAllocation_AreAccepted(int honest, int reported)
    {
        var attributes = Read(new LyingLengthFake(honest, reported));

        using var attribute = attributes[0];
        Assert.Equal(reported, (int)attribute.ValueLength);
    }

    [Fact]
    public void AnHonestModule_IsUnaffected()
    {
        var attributes = Read(new HonestFake(len: 16));

        using var attribute = attributes[0];
        Assert.Equal(16, (int)attribute.ValueLength);
    }
}
