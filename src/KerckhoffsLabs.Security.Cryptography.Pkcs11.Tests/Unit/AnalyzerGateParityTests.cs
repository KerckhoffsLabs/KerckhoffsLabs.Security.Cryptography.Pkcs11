using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Generators;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// The compile-time diagnostics warn about exactly what the default policy documents as refused: its
/// documented deny list, not every mechanism it merely has not reviewed. The analyzer
/// cannot reference the library (it targets netstandard2.0 and would be a cycle), so its mechanism list
/// is a transcription of <c>CryptoPolicy.Recommended</c>'s documented refusals — and a transcription can drift.
/// These tests pin the two together in both directions: a documented refusal the analyzer stays silent
/// on is a missed warning; the reverse is a warning with no documented reason behind it.
/// </summary>
public sealed class AnalyzerGateParityTests
{
    // KLPKCS11008 owns the RSA-encryption pair; KLPKCS11009 owns every other documented refusal.
    private static readonly string[] RsaPaddingRuleMechanisms =
        [nameof(CKM.CKM_RSA_PKCS), nameof(CKM.CKM_RSA_X_509)];

    // Compared by CKM *value*, never by name: the enum carries spec aliases that share a value
    // (CKM_CAST128_ECB == CKM_CAST5_ECB), so a name-wise comparison reports phantom differences
    // purely from which spelling each side happens to use.
    private static HashSet<CKM> ToValues(IEnumerable<string> names)
    {
        var values = new HashSet<CKM>();
        foreach (string name in names)
        {
            Assert.True(Enum.TryParse(name, out CKM mechanism),
                $"'{name}' is not a CKM member — the analyzer would never match it.");
            values.Add(mechanism);
        }
        return values;
    }

    /// <summary>Mechanisms the default policy documents as refused.</summary>
    private static HashSet<CKM> DocumentedRefusedMechanisms()
    {
        var documented = CryptoPolicy.Recommended.Catalogue.DocumentedRefusedMechanisms.Keys.ToHashSet();
        Assert.NotEmpty(documented); // the harness itself must not silently no-op
        return documented;
    }

    private static string Describe(IEnumerable<CKM> mechanisms)
        => string.Join(", ", mechanisms.Select(m => m.ToString()).Order());

    [Fact]
    public void EveryDocumentedRefusal_IsCoveredByAnAnalyzer()
    {
        HashSet<CKM> covered = ToValues(InsecureMechanismData.GatedMechanisms.Concat(RsaPaddingRuleMechanisms));

        var missing = DocumentedRefusedMechanisms().Except(covered).ToList();

        Assert.True(missing.Count == 0,
            "Recommended documents refusals no analyzer warns about, so a consumer would only find out at " +
            "run time. Add them to InsecureMechanismData.GatedMechanisms: " + Describe(missing));
    }

    [Fact]
    public void EveryAnalyzerMechanism_IsADocumentedRefusal()
    {
        HashSet<CKM> documented = DocumentedRefusedMechanisms();

        var spurious = ToValues(InsecureMechanismData.GatedMechanisms.Concat(RsaPaddingRuleMechanisms))
            .Except(documented).ToList();

        Assert.True(spurious.Count == 0,
            "The analyzer warns about mechanisms Recommended does not document as refused — a warning " +
            "with no reason behind it: " + Describe(spurious));
    }

    [Fact]
    public void EveryAnalyzerMechanism_IsDeniedAtRunTime()
    {
        foreach (CKM mechanism in ToValues(InsecureMechanismData.GatedMechanisms.Concat(RsaPaddingRuleMechanisms)))
            foreach (CryptoOperation op in Enum.GetValues<CryptoOperation>())
                Assert.False(CryptoPolicy.Recommended.Evaluate(new MechanismUseRequest(new Mechanism(mechanism), op)).IsAllowed,
                    $"{mechanism} is flagged by an analyzer but allowed for {op}.");
    }

    [Fact]
    public void RsaPaddingRule_CoversExactlyTheRsaEncryptionMechanisms()
    {
        // Split of responsibility between the two rules: KLPKCS11008's mechanisms must be documented
        // refusals, and must not also be claimed by KLPKCS11009 (which would double-report a call site).
        Assert.Subset(DocumentedRefusedMechanisms(), ToValues(RsaPaddingRuleMechanisms));
        Assert.Empty(ToValues(RsaPaddingRuleMechanisms).Intersect(ToValues(InsecureMechanismData.GatedMechanisms)));
    }
}
