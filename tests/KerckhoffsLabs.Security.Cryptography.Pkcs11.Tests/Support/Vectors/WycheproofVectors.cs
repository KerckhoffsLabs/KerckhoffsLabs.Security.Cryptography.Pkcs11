using System.Reflection;
using System.Text.Json;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Vectors;

/// <summary>
/// Reads the C2SP Wycheproof test vectors embedded under <c>Support/Vectors/Wycheproof</c>. Each file is a verbatim copy,
/// or a subset, of one Wycheproof <c>testvectors_v1</c> file, naming its source file and commit, and saying how it was
/// cut down. Cases keep their Wycheproof <c>tcId</c>, so a failure names the published test case.
/// </summary>
internal static class WycheproofVectors
{
    // An ML-DSA (FIPS 204) verification: the published signature over msg, under the public key and the context (empty
    // when the case gives none), must verify when Result is "valid" and must not when it is "invalid".
    internal sealed record MlDsaVerification(
        string ParameterSet, int TcId, string Comment, string Result, string[] Flags, byte[] PublicKey, byte[] Message, byte[] Context,
        byte[] Signature)
    {
        public bool Valid => Result == "valid";
    }

    // A raw stream-cipher case: msg encrypted from the initial block counter (little-endian, CounterSize bits) under the
    // key and IV is ct when Result is "valid". An "invalid" case needs a block past the counter's last value, so it
    // must be refused rather than wrap the counter.
    internal sealed record StreamCipherCase(
        string Algorithm, int CounterSize, int TcId, string Comment, string Result, byte[] Key, byte[] Iv, byte[] InitialCounter,
        byte[] Message, byte[] Ciphertext)
    {
        public bool Valid => Result == "valid";
    }

    internal static IReadOnlyList<MlDsaVerification> MlDsaVerifications { get; } =
        [.. MlDsa("ML-DSA-44", "mldsa_44_verify_test.subset"),
         .. MlDsa("ML-DSA-65", "mldsa_65_verify_test.subset"),
         .. MlDsa("ML-DSA-87", "mldsa_87_verify_test.subset")];

    internal static IReadOnlyList<StreamCipherCase> ChaCha20Counter { get; } =
        Cases("chacha20_counter_test", (g, t) => new StreamCipherCase(
            Str(g, "algorithm"), Int(g, "counterSize"), Int(t, "tcId"), Str(t, "comment"), Str(t, "result"), Hex(t, "key"), Hex(t, "iv"),
            Hex(t, "initialCounter"), Hex(t, "msg"), t.TryGetProperty("ct", out JsonElement ct) ? Convert.FromHexString(ct.GetString() ?? "") : []));

    private static List<MlDsaVerification> MlDsa(string parameterSet, string file) =>
        Cases(file, (g, t) => new MlDsaVerification(
            parameterSet, Int(t, "tcId"), Str(t, "comment"), Str(t, "result"),
            [.. t.GetProperty("flags").EnumerateArray().Select(f => f.GetString() ?? "")],
            Hex(g, "publicKey"), Hex(t, "msg"), t.TryGetProperty("ctx", out JsonElement ctx) ? Convert.FromHexString(ctx.GetString() ?? "") : [],
            Hex(t, "sig")));

    private static List<T> Cases<T>(string name, Func<JsonElement, JsonElement, T> read)
    {
        using Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream($"Wycheproof.{name}.json")
            ?? throw new InvalidOperationException($"Embedded Wycheproof vectors Wycheproof.{name}.json are missing.");
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
