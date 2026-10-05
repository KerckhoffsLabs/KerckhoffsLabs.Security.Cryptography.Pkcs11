using System.Globalization;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// Compares every native struct the library declares with the layout this platform's C compiler
/// gives the same struct in the official OASIS v3.2 headers. The other layout tests are written from
/// the managed side (offsets probed from the assembly itself, or sizes derived by arithmetic), so they
/// cannot catch a mistake that was already there when they were written. This one is independent.
/// </summary>
/// <remarks>
/// <para>
/// <c>build/abi-probe.c</c> is compiled by the CI leg's own toolchain for the architecture the tests
/// run as (MSVC x86/x64/arm64 with the cryptoki <c>pack(1)</c> on Windows, gcc/clang elsewhere) and
/// writes <c>abi-oracle.txt</c> next to this assembly. On Windows the comparison uses the generated
/// <c>_Windows</c> sibling, which is the layout that actually crosses the boundary there.
/// </para>
/// <para>
/// Each member is matched by position, offset, size and name. Offsets alone would let two swapped
/// members of the same width (a pointer and its length, two <c>CK_ULONG</c>s) pass; the name check
/// catches that. C names carry Hungarian prefixes (<c>pValue</c>, <c>ulValueLen</c>) and, in a few
/// structs, snake_case, so they are compared with the prefix and underscores removed; the handful of
/// spec names that need more are listed in <see cref="NameAliases"/> with the reason.
/// </para>
/// </remarks>
public sealed class AbiOracleTests(ITestOutputHelper output)
{
    private const string NativeNs = "KerckhoffsLabs.Security.Cryptography.Pkcs11.Native";
    private const string RawNs = NativeNs + ".RawMechanismParams";
    private static readonly Assembly ProdAssembly = typeof(UnmanagedMemory).Assembly;

    /// <summary>
    /// Managed member names that differ from the C name by more than a Hungarian prefix or
    /// underscores, keyed "struct.cMember" → managed name.
    /// </summary>
    private static readonly Dictionary<string, string> NameAliases = new(StringComparer.Ordinal)
    {
        // The spec names the value length "ulValue" in this one struct.
        ["CK_ASYNC_DATA.ulValue"] = "ValueLen",
        // "ph" is "pre-hash" here, not the pointer-to-handle prefix.
        ["CK_EDDSA_PARAMS.phFlag"] = "PhFlag",
        // "s" is "salt": the PSS salt length.
        ["CK_RSA_PKCS_PSS_PARAMS.sLen"] = "Len",
        // The managed field keeps a Ptr suffix to sit next to its ulAdditionalDerivedKeys count.
        ["CK_SP800_108_KDF_PARAMS.pAdditionalDerivedKeys"] = "AdditionalDerivedKeysPtr",
        ["CK_SP800_108_FEEDBACK_KDF_PARAMS.pAdditionalDerivedKeys"] = "AdditionalDerivedKeysPtr",
        // "e" marks an enumeration value (CK_X2RATCHET_* curve).
        ["CK_X2RATCHET_INITIALIZE_PARAMS.eCurve"] = "Curve",
        ["CK_X2RATCHET_RESPOND_PARAMS.eCurve"] = "Curve",
    };

    private static readonly Lazy<IReadOnlyDictionary<string, CStruct>?> Oracle = new(LoadOracle);

    [Fact]
    public void EveryManagedStruct_HasAnOracleRow()
    {
        IReadOnlyDictionary<string, CStruct> oracle = RequireOracle();

        string[] unknown = [.. ManagedStructs().Select(t => t.Name).Where(n => !oracle.ContainsKey(n)).Order(StringComparer.Ordinal)];
        Assert.True(unknown.Length == 0, "Managed structs with no struct of that name in the OASIS headers: " + string.Join(", ", unknown));

        // The census must not pass vacuously: the managed set and the oracle are both large.
        Assert.True(ManagedStructs().Count() > 80, $"Only {ManagedStructs().Count()} managed CK_* structs found.");
    }

    [Fact]
    public void EveryManagedStruct_MatchesTheCompilerLayout()
    {
        IReadOnlyDictionary<string, CStruct> oracle = RequireOracle();
        var failures = new List<string>();
        int checkedMembers = 0;

        // A struct with no oracle row is reported by EveryManagedStruct_HasAnOracleRow.
        foreach (Type type in ManagedStructs().Where(t => oracle.ContainsKey(t.Name)))
        {
            CStruct c = oracle[type.Name];
            Type layout = PlatformLayout(type);
            FieldInfo[] fields = InstanceFields(layout);

            int size = RuntimeHelpers.SizeOf(layout.TypeHandle);
            if (size != c.Size)
                failures.Add($"{type.Name}: size {size}, C says {c.Size}");

            if (fields.Length != c.Members.Count)
            {
                failures.Add($"{type.Name}: {fields.Length} members [{string.Join(", ", fields.Select(f => f.Name))}], " +
                             $"C has {c.Members.Count} [{string.Join(", ", c.Members.Select(m => m.Name))}]");
                continue;
            }

            for (int i = 0; i < fields.Length; i++)
            {
                FieldInfo f = fields[i];
                CMember m = c.Members[i];
                int offset = (int)Marshal.OffsetOf(layout, f.Name);
                int memberSize = SizeOfField(f);
                string where = $"{type.Name} member {i} ({f.Name} ↔ {m.Name})";

                if (!NamesCorrespond(type.Name, m.Name, f.Name))
                    failures.Add($"{where}: names do not correspond");
                if (offset != m.Offset)
                    failures.Add($"{where}: offset {offset}, C says {m.Offset}");
                if (memberSize != m.Size)
                    failures.Add($"{where}: size {memberSize}, C says {m.Size}");
                checkedMembers++;
            }
        }

        Assert.True(failures.Count == 0, $"{failures.Count} layout differences on {RuntimeInformation.RuntimeIdentifier}:\n" + string.Join("\n", failures));
        output.WriteLine($"{checkedMembers} members checked against the {RuntimeInformation.RuntimeIdentifier} compiler layout.");
    }

    [Fact]
    public void HeaderStructsWithoutAManagedCounterpart_AreReported()
    {
        IReadOnlyDictionary<string, CStruct> oracle = RequireOracle();
        var managed = ManagedStructs().Select(t => t.Name).ToHashSet(StringComparer.Ordinal);

        output.WriteLine("OASIS v3.2 structs the library does not declare:");
        foreach (string name in oracle.Keys.Where(n => !managed.Contains(n)).Order(StringComparer.Ordinal))
            output.WriteLine($"  {name}");
    }

    [Theory]
    [InlineData("pValue", "value")]
    [InlineData("ulValueLen", "valueLen")]
    [InlineData("hBaseKey", "BaseKey")]
    [InlineData("pulCount", "Count")]
    [InlineData("bIsExport", "IsExport")]
    [InlineData("manufacturerID", "ManufacturerId")]
    [InlineData("C_Sign", "C_Sign")]
    [InlineData("cb", "Cb")]
    [InlineData("(scalar)", "EffectiveBits")]
    [InlineData("pPeer_identity", "PeerIdentity")]
    [InlineData("peer_public_prekey", "PeerPublicPrekey")]
    public void HungarianPrefixes_AreIgnoredWhenMatchingNames(string cName, string managedName)
        => Assert.True(NamesCorrespond("CK_TEST", cName, managedName));

    [Theory]
    [InlineData("pIv", "IvLen")]
    [InlineData("ulIvLen", "Iv")]
    [InlineData("C_Sign", "C_SignInit")]
    public void SwappedMembers_DoNotMatch(string cName, string managedName)
        => Assert.False(NamesCorrespond("CK_TEST", cName, managedName));

    // --- matching --------------------------------------------------------------------------------

    private static bool NamesCorrespond(string structName, string cName, string managedName)
    {
        if (NameAliases.TryGetValue($"{structName}.{cName}", out string? alias))
            return alias == managedName;
        if (cName == "(scalar)")
            return true; // a C scalar typedef wrapped in a one-member struct; position, offset and size still checked
        return string.Equals(Normalized(cName), Normalized(managedName), StringComparison.OrdinalIgnoreCase);
    }

    // The Signal-protocol params use snake_case in the spec (peer_public_prekey, pPeer_identity), so
    // underscores are ignored after the prefix is removed.
    private static string Normalized(string name)
        => WithoutHungarianPrefix(name).Replace("_", "", StringComparison.Ordinal);

    // pValue → Value, ulValueLen → ValueLen, hKey → Key, pulCount → Count, bIsExport → IsExport,
    // ppInterface → Interface. A prefix counts only when an upper-case letter follows it, so names
    // that merely start with those letters (cb, pseudoRandom, type) are left alone.
    private static string WithoutHungarianPrefix(string name)
    {
        string? prefix = HungarianPrefixes.FirstOrDefault(p =>
            name.Length > p.Length && name.StartsWith(p, StringComparison.Ordinal) && char.IsAsciiLetterUpper(name[p.Length]));
        return prefix is null ? name : name[prefix.Length..];
    }

    // Longest first, so "pul" wins over "p" and "ul".
    private static readonly string[] HungarianPrefixes = ["pul", "pp", "ph", "ul", "p", "h", "b"];

    // --- managed side ----------------------------------------------------------------------------

    private static IEnumerable<Type> ManagedStructs() =>
        ProdAssembly.GetTypes().Where(t =>
            t.IsValueType && !t.IsEnum &&
            (t.Namespace == NativeNs || t.Namespace == RawNs) &&
            t.Name.StartsWith("CK_", StringComparison.Ordinal) &&
            !t.Name.EndsWith("_Windows", StringComparison.Ordinal));

    // On Windows the generated Pack=1 sibling is what reaches the module; elsewhere the struct itself.
    private static Type PlatformLayout(Type type)
        => Pkcs11Marshal.IsWindows ? ProdAssembly.GetType(type.FullName + "_Windows") ?? type : type;

    // Declaration order, which is metadata order for these sequential structs.
    private static FieldInfo[] InstanceFields(Type type)
        => [.. type.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic).OrderBy(f => f.MetadataToken)];

    private static int SizeOfField(FieldInfo field)
        => field.FieldType.IsPointer || field.FieldType.IsFunctionPointer
            ? IntPtr.Size
            : RuntimeHelpers.SizeOf(field.FieldType.TypeHandle);

    // --- oracle file -----------------------------------------------------------------------------

    private sealed record CMember(string Name, int Offset, int Size);
    private sealed record CStruct(int Size, List<CMember> Members);

    private static IReadOnlyDictionary<string, CStruct> RequireOracle()
    {
        IReadOnlyDictionary<string, CStruct>? oracle = Oracle.Value;
        if (oracle is not null)
            return oracle;

        // CI must always produce it; a missing oracle there means the probe build broke, and the
        // whole check would otherwise vanish while the run stays green.
        if (string.Equals(Environment.GetEnvironmentVariable("CI"), "true", StringComparison.OrdinalIgnoreCase))
            Assert.Fail($"abi-oracle.txt is missing from {AppContext.BaseDirectory}; the BuildAbiOracle target did not run or failed.");
        Assert.Skip("abi-oracle.txt not built (no C toolchain, or SkipAbiProbeBuild=true).");
        return null!;
    }

    private static IReadOnlyDictionary<string, CStruct>? LoadOracle()
    {
        string path = Path.Join(AppContext.BaseDirectory, "abi-oracle.txt");
        if (!File.Exists(path))
            return null;

        var structs = new Dictionary<string, CStruct>(StringComparer.Ordinal);
        foreach (string line in File.ReadLines(path))
        {
            string[] p = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            switch (p)
            {
                case ["S", var name, var size]:
                    structs[name] = new CStruct(Int(size), []);
                    break;
                case ["F", var name, var index, var member, var offset, var size]:
                    List<CMember> members = structs[name].Members;
                    Assert.Equal(Int(index), members.Count); // the probe emits members in order
                    members.Add(new CMember(member, Int(offset), Int(size)));
                    break;
                default:
                    throw new FormatException($"Unrecognised abi-oracle.txt line: '{line}'");
            }
        }
        return structs;
    }

    private static int Int(string s) => int.Parse(s, NumberStyles.None, CultureInfo.InvariantCulture);
}
