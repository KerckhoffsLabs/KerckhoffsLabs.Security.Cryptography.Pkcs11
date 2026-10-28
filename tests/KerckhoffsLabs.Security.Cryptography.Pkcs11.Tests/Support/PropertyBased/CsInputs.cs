using CsCheck;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.PropertyBased;

/// <summary>
/// CsCheck generators for the differential properties, and the runner. A length or count is drawn
/// uniformly from its range three times in four and from the range's boundary values
/// (<see cref="PropertyRuns.Edges"/>) otherwise; a byte is 0x00 or 0xFF one time in eight, so a
/// one-byte field equal to a separator turns up. On a failure CsCheck shrinks the input and reports the
/// seed that reproduces it (pass it back through <c>CsCheck_Seed</c>).
/// </summary>
internal static class CsInputs
{
    private static readonly Gen<byte> Byte = Gen.Frequency((7, Gen.Byte), (1, Gen.OneOfConst<byte>(0x00, 0xFF)));

    /// <summary>Checks <paramref name="property"/> on <see cref="PropertyRuns.Iterations"/> cases.</summary>
    internal static void Check<T>(Gen<T> inputs, Action<T> property) =>
        inputs.Sample(property, iter: PropertyRuns.Iterations, threads: 1);

    /// <summary>An integer in [<paramref name="min"/>, <paramref name="max"/>], both inclusive.</summary>
    internal static Gen<int> Int(int min, int max) =>
        Gen.Frequency((3, Gen.Int[min, max]), (1, Gen.OneOfConst(PropertyRuns.Edges(min, max))));

    /// <summary>Random bytes, exactly <paramref name="length"/> of them.</summary>
    internal static Gen<byte[]> Bytes(int length) => Byte.Array[length];

    /// <summary>Random bytes, between <paramref name="minLength"/> and <paramref name="maxLength"/> of them.</summary>
    internal static Gen<byte[]> Bytes(int minLength, int maxLength) => Int(minLength, maxLength).SelectMany(Bytes);

    /// <summary>Random bytes whose length is a multiple of <paramref name="blockSize"/>, from
    /// <paramref name="minBlocks"/> to <paramref name="maxBlocks"/> blocks.</summary>
    internal static Gen<byte[]> Blocks(int blockSize, int minBlocks, int maxBlocks) =>
        Int(minBlocks, maxBlocks).SelectMany(n => Bytes(n * blockSize));

    /// <summary><paramref name="minLength"/> to <paramref name="maxLength"/> random bytes with two cut points
    /// into them, for feeding them in three parts.</summary>
    internal static Gen<Chunked> Chunked(int maxLength, int minLength = 0) =>
        from data in Bytes(minLength, maxLength)
        from first in Int(0, data.Length)
        from second in Int(first, data.Length)
        select new Chunked(data, first, second);
}

/// <summary>Data to feed an incremental API in three parts: <c>[0, First)</c>, <c>[First, Second)</c>
/// and <c>[Second, Length)</c>. Any part may be empty.</summary>
internal sealed record Chunked(byte[] Data, int First, int Second)
{
    internal ReadOnlySpan<byte> Part1 => Data.AsSpan(0, First);

    internal ReadOnlySpan<byte> Part2 => Data.AsSpan(First, Second - First);

    internal ReadOnlySpan<byte> Part3 => Data.AsSpan(Second);

    public override string ToString() => $"{Data.Length} bytes cut at {First} and {Second}: {Convert.ToHexString(Data)}";
}
