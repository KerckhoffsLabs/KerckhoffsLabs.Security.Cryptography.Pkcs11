using System.Globalization;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.PropertyBased;

/// <summary>
/// What the property-based tests share: how many cases each property runs, and the lengths their
/// generators favour. CsCheck drives the differential properties against the BCL (<see cref="CsInputs"/>);
/// FsCheck drives the laws an adapter keeps on its own (<see cref="FsInputs"/>).
/// </summary>
/// <remarks>
/// A property runs on one thread: a PKCS#11 session is not shared between threads, and a token's
/// operation state belongs to the session. It must not skip from inside its body, where an engine would
/// take <c>Assert.Skip</c> for a failure and shrink it; capability gates (mechanism advertised, host BCL
/// support) run before the property.
/// </remarks>
internal static class PropertyRuns
{
    /// <summary>Cases per property: <c>PKCS11_TEST_PROPERTY_ITERATIONS</c>, or 16. A real token answers
    /// each case over its own C_*Init/C_* calls, so the default keeps a backend's run short; raise it
    /// locally for a deeper search.</summary>
    internal static int Iterations =>
        int.TryParse(Environment.GetEnvironmentVariable("PKCS11_TEST_PROPERTY_ITERATIONS"), NumberStyles.None, CultureInfo.InvariantCulture, out int n) && n > 0
            ? n
            : 16;

    // Lengths where off-by-one and block-boundary bugs live: empty, one byte, and either side of the
    // AES block, the hash outputs and block sizes, and the powers of two the generators reach.
    private static readonly int[] Boundaries =
        [0, 1, 2, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 71, 72, 73, 103, 104, 105, 127, 128, 129,
         135, 136, 137, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048];

    /// <summary>The boundary values within [<paramref name="min"/>, <paramref name="max"/>], the range's
    /// own ends and their neighbours included.</summary>
    internal static int[] Edges(int min, int max) =>
        [.. new[] { min, min + 1, max - 1, max }.Concat(Boundaries).Where(v => v >= min && v <= max).Distinct().Order()];
}
