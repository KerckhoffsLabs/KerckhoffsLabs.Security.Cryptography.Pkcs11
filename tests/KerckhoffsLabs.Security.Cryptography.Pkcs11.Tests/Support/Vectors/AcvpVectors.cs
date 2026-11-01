using System.Reflection;
using System.Text.Json;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Vectors;

/// <summary>
/// Reads the NIST ACVP-Server test vectors embedded under <c>Support/Vectors/Acvp</c>. Each file is a verbatim subset
/// of one ACVP <c>internalProjection.json</c>, naming its source file and commit; cases keep their ACVP <c>tgId</c> and
/// <c>tcId</c>, so a failure names the published test case.
/// </summary>
internal static class AcvpVectors
{
    internal sealed record MlKemDecapsulation(int TgId, string ParameterSet, int TcId, string Reason, byte[] Dk, byte[] C, byte[] K);

    // A signature verification or deterministic signature case of ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).
    internal sealed record PqcVerification(
        int TgId, string ParameterSet, string PreHash, int TcId, bool TestPassed, string Reason, string HashAlg,
        byte[] Pk, byte[] Message, byte[] Context, byte[] Signature);

    internal sealed record PqcSignature(int TgId, string ParameterSet, int TcId, byte[] Sk, byte[] Pk, byte[] Message, byte[] Context, byte[] Signature);

    internal static IReadOnlyList<MlKemDecapsulation> MlKemDecapsulations { get; } =
        Cases("ML-KEM-encapDecap-FIPS203", (g, t) => new MlKemDecapsulation(
            Int(g, "tgId"), Str(g, "parameterSet"), Int(t, "tcId"), Str(t, "reason"), Hex(t, "dk"), Hex(t, "c"), Hex(t, "k")));

    internal static IReadOnlyList<PqcVerification> MlDsaVerifications { get; } =
        Cases("ML-DSA-sigVer-FIPS204", (g, t) => new PqcVerification(
            Int(g, "tgId"), Str(g, "parameterSet"), Str(g, "preHash"), Int(t, "tcId"), t.GetProperty("testPassed").GetBoolean(),
            Str(t, "reason"), Str(t, "hashAlg"), Hex(t, "pk"), Hex(t, "message"), Hex(t, "context"), Hex(t, "signature")));

    internal static IReadOnlyList<PqcSignature> MlDsaDeterministicSignatures { get; } =
        Cases("ML-DSA-sigGen-FIPS204", (g, t) => new PqcSignature(
            Int(g, "tgId"), Str(g, "parameterSet"), Int(t, "tcId"), Hex(t, "sk"), Hex(t, "pk"), Hex(t, "message"), Hex(t, "context"), Hex(t, "signature")));

    internal static IReadOnlyList<PqcVerification> SlhDsaVerifications { get; } =
        Cases("SLH-DSA-sigVer-FIPS205", (g, t) => new PqcVerification(
            Int(g, "tgId"), Str(g, "parameterSet"), Str(g, "preHash"), Int(t, "tcId"), t.GetProperty("testPassed").GetBoolean(),
            Str(t, "reason"), Str(t, "hashAlg"), Hex(t, "pk"), Hex(t, "message"), Hex(t, "context"), Hex(t, "signature")));

    internal static IReadOnlyList<PqcSignature> SlhDsaDeterministicSignatures { get; } =
        Cases("SLH-DSA-sigGen-FIPS205", (g, t) => new PqcSignature(
            Int(g, "tgId"), Str(g, "parameterSet"), Int(t, "tcId"), Hex(t, "sk"), Hex(t, "pk"), Hex(t, "message"), Hex(t, "context"), Hex(t, "signature")));

    private static List<T> Cases<T>(string name, Func<JsonElement, JsonElement, T> read)
    {
        using Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream($"Acvp.{name}.subset.json")
            ?? throw new InvalidOperationException($"Embedded ACVP vectors Acvp.{name}.subset.json are missing.");
        using JsonDocument doc = JsonDocument.Parse(stream);
        List<T> cases = [];
        foreach (JsonElement group in doc.RootElement.GetProperty("testGroups").EnumerateArray())
            foreach (JsonElement test in group.GetProperty("tests").EnumerateArray())
                cases.Add(read(group, test));
        return cases;
    }

    private static int Int(JsonElement e, string name) => e.GetProperty(name).GetInt32();
    private static string Str(JsonElement e, string name) => e.GetProperty(name).GetString() ?? "";
    private static byte[] Hex(JsonElement e, string name) => Convert.FromHexString(Str(e, name));
}
