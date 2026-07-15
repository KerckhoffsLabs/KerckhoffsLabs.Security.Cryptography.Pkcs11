using System.Reflection;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Generators;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// The compile-time diagnostics are only useful if they warn about exactly what the runtime rejects.
/// The analyzer cannot reference the library (it targets netstandard2.0 and would be a cycle), so its
/// mechanism list is a transcription of <c>Pkcs11Session.GuardMechanism</c>'s switch — and a
/// transcription can drift. These tests derive the gate's *actual* behaviour by driving it over every
/// <see cref="CKM"/> value, and pin the two together in both directions: a mechanism the gate rejects
/// but the analyzer stays silent on is a missed warning; the reverse is a false alarm.
/// </summary>
public sealed class AnalyzerGateParityTests
{
    // KLPKCS11008 owns the RSA-encryption pair; KLPKCS11009 owns everything else the gate rejects.
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

    /// <summary>Mechanisms the runtime gate actually throws on, obtained by invoking it directly.</summary>
    private static HashSet<CKM> RuntimeGatedMechanisms()
    {
        var session = new Pkcs11Session(new FakeLowLevelPkcs11Library(), 1) { AllowInsecure = false };
        MethodInfo guard = typeof(Pkcs11Session)
            .GetMethod("GuardMechanism", BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new InvalidOperationException("Pkcs11Session.GuardMechanism not found — did it move?");

        var gated = new HashSet<CKM>();
        foreach (CKM mechanism in Enum.GetValues<CKM>())
        {
            try
            {
                guard.Invoke(session, [mechanism]);
            }
            catch (TargetInvocationException ex) when (ex.InnerException is InsecureOperationException)
            {
                gated.Add(mechanism);
            }
        }

        Assert.NotEmpty(gated); // the harness itself must not silently no-op
        return gated;
    }

    private static string Describe(IEnumerable<CKM> mechanisms)
        => string.Join(", ", mechanisms.Select(m => m.ToString()).Order());

    [Fact]
    public void EveryGatedMechanism_IsCoveredByAnAnalyzer()
    {
        HashSet<CKM> covered = ToValues(InsecureMechanismData.GatedMechanisms.Concat(RsaPaddingRuleMechanisms));

        var missing = RuntimeGatedMechanisms().Except(covered).ToList();

        Assert.True(missing.Count == 0,
            "The runtime gate rejects mechanisms no analyzer warns about, so a consumer would only " +
            "find out at run time. Add them to InsecureMechanismData.GatedMechanisms: " + Describe(missing));
    }

    [Fact]
    public void EveryAnalyzerMechanism_IsActuallyGated()
    {
        HashSet<CKM> gated = RuntimeGatedMechanisms();

        var spurious = ToValues(InsecureMechanismData.GatedMechanisms).Except(gated).ToList();

        Assert.True(spurious.Count == 0,
            "The analyzer warns about mechanisms the runtime gate allows — a false alarm that would " +
            "push consumers toward blanket suppressions: " + Describe(spurious));
    }

    [Fact]
    public void RsaPaddingRule_CoversExactlyTheRsaEncryptionMechanisms()
    {
        // Split of responsibility between the two rules: KLPKCS11008's mechanisms must be gated, and
        // must not also be claimed by KLPKCS11009 (which would double-report the same call site).
        Assert.Subset(RuntimeGatedMechanisms(), ToValues(RsaPaddingRuleMechanisms));
        Assert.Empty(ToValues(RsaPaddingRuleMechanisms).Intersect(ToValues(InsecureMechanismData.GatedMechanisms)));
    }
}
