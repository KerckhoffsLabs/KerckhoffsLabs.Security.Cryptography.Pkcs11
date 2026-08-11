using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// The span-based RNG entry points must not leave a second copy of the material on the GC heap.
/// The interop layer takes spans, so the caller's buffer reaches the token untouched and there is
/// no transient array to zero — but "no transient" is only observable by identity, so these tests
/// capture the address the fake was handed and compare it with the caller's own pinned buffer.
/// A copy anywhere in between would show a different address.
/// </summary>
public sealed class Pkcs11SessionRandomZeroizationTests
{
    private const ulong SessionId = 21;

    private sealed class RngFake : FakeLowLevelPkcs11Library
    {
        /// <summary>Address of the buffer the session handed to the interop layer.</summary>
        public IntPtr SeenAddress { get; private set; }

        /// <summary>Length of that buffer, so a truncated view would be caught too.</summary>
        public int SeenLength { get; private set; }

        public byte[] TokenOutput = [0xA1, 0xA2, 0xA3, 0xA4];

        public override unsafe CKR C_GenerateRandom(NativeCULong session, Span<byte> randomData)
        {
            fixed (byte* p = randomData)
                SeenAddress = (IntPtr)p;
            SeenLength = randomData.Length;
            TokenOutput.AsSpan(0, randomData.Length).CopyTo(randomData);
            return CKR.CKR_OK;
        }

        public override unsafe CKR C_SeedRandom(NativeCULong session, ReadOnlySpan<byte> seed)
        {
            fixed (byte* p = seed)
                SeenAddress = (IntPtr)p;
            SeenLength = seed.Length;
            return CKR.CKR_OK;
        }
    }

    [Fact]
    public unsafe void GenerateRandom_Span_FillsTheCallersBufferWithNoTransientCopy()
    {
        var fake = new RngFake { TokenOutput = [0xA1, 0xA2, 0xA3, 0xA4] };
        var session = new Pkcs11Session(fake, SessionId);
        Span<byte> destination = stackalloc byte[4];

        int written = session.GenerateRandom(destination);

        fixed (byte* p = destination)
            Assert.Equal((IntPtr)p, fake.SeenAddress);              // the token wrote here, not into a copy
        Assert.Equal(4, written);
        Assert.Equal(4, fake.SeenLength);
        Assert.Equal(new byte[] { 0xA1, 0xA2, 0xA3, 0xA4 }, destination.ToArray());
    }

    [Fact]
    public unsafe void SeedRandom_Span_PassesTheCallersEntropyStraightThrough()
    {
        var fake = new RngFake();
        var session = new Pkcs11Session(fake, SessionId);
        byte[] entropy = [0xE1, 0xE2, 0xE3, 0xE4];

        fixed (byte* p = entropy)
        {
            session.SeedRandom(entropy.AsSpan());
            Assert.Equal((IntPtr)p, fake.SeenAddress);              // no transient copy of the entropy
        }

        Assert.Equal(4, fake.SeenLength);
        Assert.Equal(new byte[] { 0xE1, 0xE2, 0xE3, 0xE4 }, entropy); // the caller's buffer is untouched
    }
}
