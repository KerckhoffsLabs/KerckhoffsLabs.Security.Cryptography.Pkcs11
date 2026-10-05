using System.Globalization;
using System.Reflection;
using System.Text.RegularExpressions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Common;

/// <summary>
/// Checks every PKCS#11 constant the library declares against the official OASIS v3.2
/// <c>pkcs11t.h</c> (the <c>vendor/pkcs11</c> submodule, <c>published/3-02/</c>). <c>CKM</c> and
/// <c>CKR</c> alone are thousands of hand-typed literals, and one wrong digit silently selects a
/// different mechanism or mis-maps an error; a one-off review cannot keep that true, this test does.
/// </summary>
/// <remarks>
/// Direction matters:
/// <list type="bullet">
///   <item><description>
///     Library → header is enforced. Every public constant named like a header constant (a <c>CK</c>
///     prefix) must exist in the header with the same value.
///   </description></item>
///   <item><description>
///     Header → library is reported, not enforced. Not every header constant is meant to be exposed,
///     so the ones the library lacks are written to the test output for review.
///   </description></item>
/// </list>
/// </remarks>
public sealed partial class HeaderConstantParityTests(ITestOutputHelper output)
{
    private const string CommonNamespace = "KerckhoffsLabs.Security.Cryptography.Pkcs11.Common";

    /// <summary>
    /// Public constants that are deliberately not in the OASIS header (vendor-defined values, say),
    /// keyed by declaring type and name. Empty today; add an entry with the reason when one is needed.
    /// </summary>
    private static readonly HashSet<string> NotInHeader = [];

    private static readonly Lazy<IReadOnlyDictionary<string, ulong>> HeaderConstants = new(LoadHeaderConstants);

    [Fact]
    public void EveryLibraryConstant_MatchesTheOasisHeader()
    {
        IReadOnlyDictionary<string, ulong> header = HeaderConstants.Value;
        var mismatches = new List<string>();
        var missing = new List<string>();

        foreach ((string owner, string name, ulong value) in LibraryConstants())
        {
            if (NotInHeader.Contains($"{owner}.{name}"))
                continue;

            if (!header.TryGetValue(name, out ulong expected))
                missing.Add($"{owner}.{name} = 0x{value:X}");
            else if (expected != value)
                mismatches.Add($"{owner}.{name} = 0x{value:X}, header says 0x{expected:X}");
        }

        Assert.True(mismatches.Count == 0,
            "Constants whose value differs from pkcs11t.h:\n" + string.Join("\n", mismatches));
        Assert.True(missing.Count == 0,
            "Constants not defined in pkcs11t.h (fix the name, or list them in NotInHeader with the reason):\n"
            + string.Join("\n", missing));
    }

    // Guards the test itself: without this, a broken parser or a renamed namespace would leave the
    // comparison above with nothing to compare, and it would pass.
    [Fact]
    public void ParityCheck_CoversTheWholeSurface()
    {
        Assert.True(HeaderConstants.Value.Count > 1000, $"Parsed only {HeaderConstants.Value.Count} header constants.");
        Assert.True(LibraryConstants().Count() > 1000, $"Found only {LibraryConstants().Count()} library constants.");
    }

    [Fact]
    public void HeaderConstantsAbsentFromTheLibrary_AreReported()
    {
        var declared = LibraryConstants().Select(c => c.Name).ToHashSet(StringComparer.Ordinal);
        string[] absent = [.. HeaderConstants.Value.Keys.Where(n => !declared.Contains(n)).Order(StringComparer.Ordinal)];

        output.WriteLine($"{absent.Length} pkcs11t.h constants have no library counterpart:");
        foreach (string name in absent)
            output.WriteLine($"  {name}");

        // A report listing the whole header means the library side matched nothing, so the list
        // would be noise rather than the gaps it is meant to show.
        Assert.True(absent.Length < HeaderConstants.Value.Count,
            $"All {absent.Length} header constants were reported absent; the library side matched none.");
    }

    [Theory]
    [InlineData("0x00000001UL", 1UL)]
    [InlineData("0x8000000UL", 0x8000000UL)]
    [InlineData("12", 12UL)]
    [InlineData("(~0UL)", ulong.MaxValue)]
    [InlineData("(CKF_ARRAY_ATTRIBUTE|0x00000211UL)", 0x40000211UL)]
    [InlineData("CKA_SUBPRIME_BITS", 0x134UL)]
    public void Evaluator_HandlesEveryExpressionShapeInTheHeader(string expression, ulong expected)
    {
        var defines = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["CKF_ARRAY_ATTRIBUTE"] = "0x40000000UL",
            ["CKA_SUBPRIME_BITS"] = "0x00000134UL",
        };
        Assert.Equal(expected, Evaluate(expression, defines, depth: 0));
    }

    [Theory]
    [InlineData("\n")]
    [InlineData("\r\n")]
    public void ParseDefines_ReadsEveryDefine_WhateverTheLineEndings(string newline)
    {
        string text = string.Join(newline,
            "#define CKM_DSA_PROBABILISTIC_PARAMETER_GEN 0x00002003UL",
            "#define CKM_DSA_PROBABLISTIC_PARAMETER_GEN CKM_DSA_PROBABILISTIC_PARAMETER_GEN /* Depricated */",
            "");

        Dictionary<string, string> defines = ParseDefines(text);

        Assert.Equal("0x00002003UL", defines["CKM_DSA_PROBABILISTIC_PARAMETER_GEN"]);
        Assert.Equal(0x2003UL, Evaluate(defines["CKM_DSA_PROBABLISTIC_PARAMETER_GEN"], defines, depth: 0));
    }

    // --- library side --------------------------------------------------------------------------

    private static IEnumerable<(string Owner, string Name, ulong Value)> LibraryConstants()
    {
        IEnumerable<Type> types = typeof(CKA).Assembly.GetExportedTypes()
            .Where(t => t.Namespace == CommonNamespace && (t.IsEnum || (t.IsAbstract && t.IsSealed)));

        foreach (Type type in types)
        {
            IEnumerable<FieldInfo> constants = type.IsEnum
                ? type.GetFields(BindingFlags.Public | BindingFlags.Static)
                : type.GetFields(BindingFlags.Public | BindingFlags.Static).Where(f => f.IsLiteral && f.FieldType == typeof(ulong));

            foreach (FieldInfo field in constants.Where(f => IsHeaderStyleName(f.Name)))
                yield return (type.Name, field.Name, Convert.ToUInt64(field.GetRawConstantValue(), CultureInfo.InvariantCulture));
        }
    }

    // Header constants are CK-prefixed upper-case identifiers (CKA_CLASS, CK_INVALID_HANDLE). Members
    // with managed-style names, such as Sp800108DkmLengthMethod.SumOfKeys, are not header constants.
    private static bool IsHeaderStyleName(string name) => HeaderStyleName().IsMatch(name);

    [GeneratedRegex("^CK[A-Z]?_[A-Z0-9_]+$", RegexOptions.CultureInvariant)]
    private static partial Regex HeaderStyleName();

    // --- header side ---------------------------------------------------------------------------

    private static Dictionary<string, ulong> LoadHeaderConstants()
    {
        string path = Path.Join(AppContext.BaseDirectory, "pkcs11-v3.2", "pkcs11t.h");
        Assert.True(File.Exists(path), $"OASIS header not found at {path}; the test project copies it from the vendor/pkcs11 submodule (git submodule update --init vendor/pkcs11).");

        Dictionary<string, string> defines = ParseDefines(File.ReadAllText(path));

        var values = new Dictionary<string, ulong>(StringComparer.Ordinal);
        foreach (string name in defines.Keys)
            values[name] = Evaluate(defines[name], defines, depth: 0);
        return values;
    }

    // The header comes from a submodule, which the repo's .gitattributes (eol=lf) does not reach, so a
    // Windows checkout with core.autocrlf writes it with CRLF. Define() anchors on the end of the line,
    // and a stray '\r' there drops every define without a trailing comment, so normalize first.
    private static Dictionary<string, string> ParseDefines(string headerText)
    {
        var defines = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (Match m in Define().Matches(headerText.ReplaceLineEndings("\n")))
            defines[m.Groups["name"].Value] = m.Groups["value"].Value.Trim();
        return defines;
    }

    // "#define CKA_CLASS 0x00000000UL /* comment */" → name, value (comment excluded). Only CK-prefixed
    // object-like macros carry constant values; function-like macros and include guards are skipped.
    [GeneratedRegex(@"^[ \t]*#[ \t]*define[ \t]+(?<name>CK\w*)[ \t]+(?<value>[^/\r\n]+?)[ \t]*(?:/\*.*)?$", RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex Define();

    /// <summary>
    /// Evaluates a pkcs11t.h constant expression. The header uses exactly these shapes: a decimal or
    /// hex literal with an optional <c>U</c>/<c>L</c> suffix, a reference to another constant,
    /// <c>(A|B)</c>, and <c>(~0UL)</c>. Anything else throws, so a new shape in a future header fails
    /// loudly instead of being misread.
    /// </summary>
    private static ulong Evaluate(string expression, IReadOnlyDictionary<string, string> defines, int depth)
    {
        if (depth > 16)
            throw new InvalidOperationException($"Constant reference chain too deep at '{expression}'.");

        string e = expression.Trim();
        while (e.StartsWith('(') && e.EndsWith(')'))
            e = e[1..^1].Trim();

        if (e.Contains('|', StringComparison.Ordinal))
            return e.Split('|').Aggregate(0UL, (acc, part) => acc | Evaluate(part, defines, depth + 1));

        if (e.StartsWith('~'))
            return ~Evaluate(e[1..], defines, depth + 1);

        string literal = e.TrimEnd('U', 'u', 'L', 'l');
        if (literal.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return ulong.Parse(literal[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        if (literal.Length > 0 && literal.All(char.IsAsciiDigit))
            return ulong.Parse(literal, CultureInfo.InvariantCulture);

        if (defines.TryGetValue(e, out string? referenced))
            return Evaluate(referenced, defines, depth + 1);

        throw new FormatException($"Unrecognised constant expression '{expression}' in pkcs11t.h.");
    }
}
