// Licensed under the MIT License

using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// The span-based RNG entry points must not leave a second copy of the material on the GC heap. The
/// interop signatures take <c>byte[]</c>, so a transient array is unavoidable between the token and
/// the caller's span — but it is freshly generated key material (or the entropy that will produce
/// it), and the whole reason a caller passes a span is to control where that material lives. These
/// tests keep the transient reachable through the fake so its contents can be inspected after the
/// call returns, which is the only way to observe the zeroization from outside.
/// </summary>
public sealed class Pkcs11SessionRandomZeroizationTests
{
    private const ulong SessionId = 21;

    private sealed class RngFake : FakeLowLevelPkcs11Library
    {
        /// <summary>The exact array the session handed to the interop layer.</summary>
        public byte[]? Transient { get; private set; }

        public byte[] TokenOutput = [0xA1, 0xA2, 0xA3, 0xA4];

        public override CKR C_GenerateRandom(NativeCULong session, byte[] randomData, NativeCULong randomLen)
        {
            Transient = randomData;
            TokenOutput.AsSpan(0, (int)randomLen).CopyTo(randomData);
            return CKR.CKR_OK;
        }

        public override CKR C_SeedRandom(NativeCULong session, byte[] seed, NativeCULong seedLen)
        {
            Transient = seed;
            return CKR.CKR_OK;
        }
    }

    [Fact]
    public void GenerateRandom_Span_ZeroesTheTransient_AfterFillingTheDestination()
    {
        var fake = new RngFake { TokenOutput = [0xA1, 0xA2, 0xA3, 0xA4] };
        var session = new Pkcs11Session(fake, SessionId);
        Span<byte> destination = stackalloc byte[4];

        int written = session.GenerateRandom(destination);

        Assert.Equal(4, written);
        Assert.Equal(new byte[] { 0xA1, 0xA2, 0xA3, 0xA4 }, destination.ToArray()); // caller still gets the data
        Assert.NotNull(fake.Transient);
        Assert.All(fake.Transient!, b => Assert.Equal(0, b));                        // ...and no copy survives
    }

    [Fact]
    public void SeedRandom_Span_ZeroesTheTransientCopyOfTheCallersEntropy()
    {
        var fake = new RngFake();
        var session = new Pkcs11Session(fake, SessionId);
        byte[] entropy = [0xE1, 0xE2, 0xE3, 0xE4];

        session.SeedRandom(entropy.AsSpan());

        Assert.NotNull(fake.Transient);
        Assert.NotSame(entropy, fake.Transient);                    // the interop copy is a distinct array
        Assert.All(fake.Transient!, b => Assert.Equal(0, b));       // which must not outlive the call
        Assert.Equal(new byte[] { 0xE1, 0xE2, 0xE3, 0xE4 }, entropy); // the caller's own buffer is untouched
    }
}
