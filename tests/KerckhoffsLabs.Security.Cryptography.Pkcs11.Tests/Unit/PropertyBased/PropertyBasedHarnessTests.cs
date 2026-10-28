using CsCheck;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.PropertyBased;
using FsGen = FsCheck.Fluent.Gen;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.PropertyBased;

// The harness the property-based tests stand on. A runner that skipped its cases, or swallowed a failure,
// would let every property pass without checking anything, and a generator or shrinker that left its
// range would hand a token input the property never meant to send; these pin that neither happens.
public sealed class PropertyBasedHarnessTests
{
    private const int Samples = 500;

    // === PropertyRuns ======================================================================

    [Fact]
    public void Edges_AreTheBoundariesInsideTheRange_TheEndsIncluded()
    {
        int[] edges = PropertyRuns.Edges(10, 40);

        Assert.Equal([10, 11, 15, 16, 17, 31, 32, 33, 39, 40], edges);
    }

    [Fact]
    public void Edges_OfASingleValue_IsThatValue() => Assert.Equal([7], PropertyRuns.Edges(7, 7));

    // === CsInputs (CsCheck) ================================================================

    [Fact]
    public void CsCheck_RunsTheConfiguredIterations()
    {
        int calls = 0;

        CsInputs.Check(CsInputs.Int(0, 9), _ => calls++);

        Assert.Equal(PropertyRuns.Iterations, calls);
    }

    [Fact]
    public void CsCheck_AFailureThrowsWithTheSeed()
    {
        var ex = Assert.Throws<CsCheck.CsCheckException>(() => CsInputs.Check(CsInputs.Int(0, 9), _ => Assert.Fail("refuted")));

        Assert.Contains("CsCheck_Seed", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void CsInt_StaysInRange_AndDrawsBothEnds()
    {
        var seen = new HashSet<int>();
        CsInputs.Int(3, 300).Sample(v => { Assert.InRange(v, 3, 300); seen.Add(v); }, iter: Samples, threads: 1);

        Assert.Contains(3, seen);
        Assert.Contains(300, seen);
    }

    [Fact]
    public void CsBytes_StayWithinTheirLengthRange() =>
        CsInputs.Bytes(3, 7).Sample(b => Assert.InRange(b.Length, 3, 7), iter: Samples, threads: 1);

    [Fact]
    public void CsBytes_DrawZeroAndFfBytesOften()
    {
        int zeros = 0, ffs = 0, total = 0;
        CsInputs.Bytes(64).Sample(b => { zeros += b.Count(x => x == 0x00); ffs += b.Count(x => x == 0xFF); total += b.Length; }, iter: 100, threads: 1);

        // One byte in eight is 0x00 or 0xFF by weight, against one in 128 uniformly.
        Assert.InRange(zeros, total / 32, total / 8);
        Assert.InRange(ffs, total / 32, total / 8);
    }

    [Fact]
    public void CsBlocks_AreWholeBlocks() =>
        CsInputs.Blocks(16, 1, 4).Sample(b =>
        {
            Assert.InRange(b.Length, 16, 64);
            Assert.Equal(0, b.Length % 16);
        }, iter: Samples, threads: 1);

    [Fact]
    public void CsChunked_CutsInsideTheData() =>
        CsInputs.Chunked(maxLength: 40, minLength: 5).Sample(chunked =>
        {
            Assert.InRange(chunked.Data.Length, 5, 40);
            Assert.InRange(chunked.First, 0, chunked.Second);
            Assert.InRange(chunked.Second, chunked.First, chunked.Data.Length);
            byte[] joined = [.. chunked.Part1, .. chunked.Part2, .. chunked.Part3];
            Assert.Equal(chunked.Data, joined);
        }, iter: Samples, threads: 1);

    // === FsInputs (FsCheck) ================================================================

    [Fact]
    public void FsCheck_RunsTheConfiguredIterations()
    {
        int calls = 0;

        FsInputs.Check(FsInputs.Int(0, 9), _ => calls++);

        Assert.Equal(PropertyRuns.Iterations, calls);
    }

    [Fact]
    public void FsCheck_AFailureThrowsWithTheReplaySeed()
    {
        var ex = Assert.ThrowsAny<Exception>(() => FsInputs.Check(FsInputs.Int(0, 9), _ => Assert.Fail("refuted")));

        Assert.Contains("Falsifiable", ex.Message, StringComparison.Ordinal);
        Assert.Contains("Replay", ex.Message, StringComparison.Ordinal);
    }

    // The counterexample is shrunk to the smallest failing value: the first length the property refuses.
    [Fact]
    public void FsCheck_ShrinksACounterexampleToTheMinimalOne()
    {
        var ex = Assert.ThrowsAny<Exception>(() =>
            FsInputs.Check(FsInputs.Bytes(2, 200), bytes => Assert.True(bytes.Length < 10)));

        Assert.Contains("Shrunk", ex.Message, StringComparison.Ordinal);
        string shrunk = ex.Message[ex.Message.IndexOf("Shrunk", StringComparison.Ordinal)..];
        Assert.Equal(10, shrunk.Split("uy", StringSplitOptions.None).Length - 1);
    }

    [Fact]
    public void FsInt_GeneratesAndShrinksWithinRange()
    {
        var arbitrary = FsInputs.Int(3, 300);

        foreach (int value in FsGen.Sample(arbitrary.Generator, Samples))
        {
            Assert.InRange(value, 3, 300);
            Assert.All(arbitrary.Shrinker(value), s => Assert.InRange(s, 3, value - 1));
        }
    }

    [Fact]
    public void FsBytes_NeverShrinkBelowTheirMinimumLength()
    {
        var arbitrary = FsInputs.Bytes(3, 40);

        foreach (byte[] value in FsGen.Sample(arbitrary.Generator, Samples))
        {
            Assert.InRange(value.Length, 3, 40);
            Assert.All(arbitrary.Shrinker(value), s => Assert.InRange(s.Length, 3, value.Length));
        }
    }

    [Fact]
    public void FsBytesOfLength_KeepTheirLengthWhenShrunk()
    {
        var arbitrary = FsInputs.BytesOfLength(16, 32);

        foreach (byte[] value in FsGen.Sample(arbitrary.Generator, Samples))
        {
            Assert.Contains(value.Length, new[] { 16, 32 });
            Assert.All(arbitrary.Shrinker(value), s => Assert.Equal(value.Length, s.Length));
        }
    }

    [Fact]
    public void FsOneOf_ShrinksTowardTheFirstValue()
    {
        var arbitrary = FsInputs.OneOf(16, 12, 14);

        Assert.Equal([16, 12], arbitrary.Shrinker(14));
        Assert.Empty(arbitrary.Shrinker(16));
    }

    [Fact]
    public void FsZip_ShrinksEachHalfOnItsOwn()
    {
        var arbitrary = FsInputs.Zip(FsInputs.Int(0, 10), FsInputs.Int(0, 10));

        Assert.All(arbitrary.Shrinker((4, 6)), pair => Assert.True(pair.Item1 == 4 ^ pair.Item2 == 6));
    }

    // === Tampering =========================================================================

    [Fact]
    public void FlipBit_FlipsExactlyOneBit_WrappingTheIndex()
    {
        byte[] value = [0x00, 0x00, 0x00];

        Assert.Equal([0x00, 0x04, 0x00], FsInputs.FlipBit(value, 10));
        Assert.Equal([0x00, 0x04, 0x00], FsInputs.FlipBit(value, 10 + 24));
        Assert.Equal([0x00, 0x00, 0x00], value);
    }

    [Fact]
    public void FlipBit_ChangesTheValueForEveryIndex()
    {
        byte[] value = [0x5A, 0xA5];

        for (int bit = 0; bit < 16; bit++)
            Assert.NotEqual(value, FsInputs.FlipBit(value, bit));
    }
}
