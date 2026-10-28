using FsCheck;
using FsCheck.Fluent;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.PropertyBased;

/// <summary>
/// FsCheck arbitraries for the algorithm laws, and the runner. The generators favour the same lengths
/// and bytes as <see cref="CsInputs"/>; every arbitrary carries a shrinker that keeps its value valid (a
/// length stays in its range, a key keeps its size), so a counterexample shrinks to a minimal one. On a
/// failure FsCheck reports the seed that replays it.
/// </summary>
/// <remarks>
/// <para>
/// The laws run from <c>[Fact]</c> and <c>[Theory]</c> through FsCheck's <c>Check.One</c>
/// rather than FsCheck.Xunit's <c>[Property]</c>: <c>[Property]</c> reports an <c>Assert.Skip</c> from the
/// test body as a failure, and these tests skip at run time when a backend lacks the mechanism.
/// </para>
/// <para>
/// The shrinkers take few, large steps. FsCheck puts no bound on shrinking, and every candidate it tries
/// runs the property again on the token: its own array shrinker, which removes or shrinks one element at
/// a time, makes thousands of token calls on a 1 KB message, holding a test thread for the whole of it
/// (enough, on a four-core CI runner, to stall every collection). A byte array here tries all zeros, then
/// half its length, then one byte fewer: halving is logarithmic in the length, and only the last steps
/// trim a byte at a time.
/// </para>
/// </remarks>
internal static class FsInputs
{
    private static readonly Gen<byte> Byte = Gen.Frequency(
        (7, Gen.Choose(0, 255).Select(static i => (byte)i)),
        (1, Gen.Elements<byte>(0x00, 0xFF)));

    private static Config Config => Config.QuickThrowOnFailure.WithMaxTest(PropertyRuns.Iterations).WithQuietOnSuccess(true);

    /// <summary>Checks <paramref name="property"/> on <see cref="PropertyRuns.Iterations"/> cases.</summary>
    internal static void Check<T>(Arbitrary<T> inputs, Action<T> property) =>
        FsCheck.Check.One(Config, Prop.ForAll(inputs, property));

    /// <inheritdoc cref="Check{T}(Arbitrary{T}, Action{T})"/>
    internal static void Check<T1, T2>(Arbitrary<T1> first, Arbitrary<T2> second, Action<T1, T2> property) =>
        FsCheck.Check.One(Config, Prop.ForAll(first, second, property));

    /// <inheritdoc cref="Check{T}(Arbitrary{T}, Action{T})"/>
    internal static void Check<T1, T2, T3>(Arbitrary<T1> first, Arbitrary<T2> second, Arbitrary<T3> third, Action<T1, T2, T3> property) =>
        FsCheck.Check.One(Config, Prop.ForAll(first, second, third, property));

    /// <summary>An integer in [<paramref name="min"/>, <paramref name="max"/>], shrinking toward <paramref name="min"/>.</summary>
    internal static Arbitrary<int> Int(int min, int max) =>
        Arb.From(IntGen(min, max), value => ShrinkTowards(value, min));

    /// <summary>One of <paramref name="values"/>, shrinking toward the first.</summary>
    internal static Arbitrary<T> OneOf<T>(params T[] values) =>
        Arb.From(Gen.Elements(values), value => values.TakeWhile(v => !EqualityComparer<T>.Default.Equals(v, value)));

    /// <summary>Random bytes, between <paramref name="minLength"/> and <paramref name="maxLength"/> of them,
    /// shrinking toward fewer and smaller bytes but never below <paramref name="minLength"/>.</summary>
    internal static Arbitrary<byte[]> Bytes(int minLength, int maxLength) =>
        Arb.From(
            IntGen(minLength, maxLength).SelectMany(n => Gen.ArrayOf(Byte, n)),
            bytes => ShrinkBytes(bytes, minLength));

    /// <summary>Random bytes of one of <paramref name="lengths"/>, a key size for instance: shrinking
    /// changes the bytes, never the length.</summary>
    internal static Arbitrary<byte[]> BytesOfLength(params int[] lengths) =>
        Arb.From(
            Gen.Elements(lengths).SelectMany(n => Gen.ArrayOf(Byte, n)),
            bytes => ShrinkBytes(bytes, bytes.Length));

    /// <summary>A bit to flip, as an index to take modulo the length in bits of what is tampered with,
    /// shrinking toward bit 0.</summary>
    internal static Arbitrary<int> BitIndex() =>
        Arb.From(Gen.Choose(0, int.MaxValue), value => ShrinkTowards(value, 0));

    /// <summary>Two arbitraries as one, each half shrinking on its own.</summary>
    internal static Arbitrary<(T1, T2)> Zip<T1, T2>(Arbitrary<T1> first, Arbitrary<T2> second) =>
        Arb.From(
            from a in first.Generator
            from b in second.Generator
            select (a, b),
            pair => first.Shrinker(pair.Item1).Select(a => (a, pair.Item2))
                .Concat(second.Shrinker(pair.Item2).Select(b => (pair.Item1, b))));

    /// <summary>Three arbitraries as one, each part shrinking on its own.</summary>
    internal static Arbitrary<(T1, T2, T3)> Zip<T1, T2, T3>(Arbitrary<T1> first, Arbitrary<T2> second, Arbitrary<T3> third) =>
        Arb.From(
            from a in first.Generator
            from b in second.Generator
            from c in third.Generator
            select (a, b, c),
            triple => first.Shrinker(triple.Item1).Select(a => (a, triple.Item2, triple.Item3))
                .Concat(second.Shrinker(triple.Item2).Select(b => (triple.Item1, b, triple.Item3)))
                .Concat(third.Shrinker(triple.Item3).Select(c => (triple.Item1, triple.Item2, c))));

    /// <summary>Flips bit <paramref name="bitIndex"/> (modulo its length in bits) of a copy of
    /// <paramref name="value"/>, which must not be empty.</summary>
    internal static byte[] FlipBit(byte[] value, int bitIndex)
    {
        byte[] copy = [.. value];
        int bit = bitIndex % (copy.Length * 8);
        copy[bit / 8] ^= (byte)(1 << (bit % 8));
        return copy;
    }

    private static Gen<int> IntGen(int min, int max) =>
        Gen.Frequency((3, Gen.Choose(min, max)), (1, Gen.Elements(PropertyRuns.Edges(min, max))));

    // All zeros, then half the length, then one byte shorter, never below minLength.
    private static IEnumerable<byte[]> ShrinkBytes(byte[] bytes, int minLength)
    {
        if (bytes.AsSpan().ContainsAnyExcept((byte)0))
            yield return new byte[bytes.Length];
        if (bytes.Length / 2 >= minLength && bytes.Length / 2 < bytes.Length - 1)
            yield return bytes[..(bytes.Length / 2)];
        if (bytes.Length > minLength)
            yield return bytes[..^1];
    }

    // The bound itself, then values halfway closer to it, ending one step away.
    private static IEnumerable<int> ShrinkTowards(int value, int bound)
    {
        if (value == bound)
            yield break;
        yield return bound;
        for (long step = ((long)value - bound) / 2; step > 0; step /= 2)
            yield return (int)(value - step);
    }
}
