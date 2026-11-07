using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.LayerDependencies;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Architecture;

/// <summary>
/// <c>Algorithms</c> adapts the façade to the BCL's algorithm types, so it should be buildable by a consumer:
/// only from what the library makes public. <see cref="AlgorithmsLayerDependencyTests"/> checks the namespaces
/// it uses, not the accessibility of what it calls in them, so an <c>internal</c> member of <c>Pkcs11Key</c> or
/// <c>Pkcs11Session</c> passes that test. This one lists every non-public type or member outside
/// <c>Algorithms</c> that it reaches. <see cref="Known"/> holds those it reached when the test was added: it
/// may only shrink.
/// </summary>
public sealed class AlgorithmsPublicSurfaceTests
{
    private const string Layer = $"{Root}.Algorithms";

    // Each entry is a reason an adapter could not be written outside this assembly. Remove an entry once
    // nothing in Algorithms needs it; never add one: make the member public, or move the work behind a
    // public façade method, instead.
    private static readonly string[] Known =
    [
        // The key's session, and the policy checks the adapters run on it themselves.
        "Pkcs11Key.get_Session",
        "Pkcs11Session.Enforce",
        "Pkcs11Session.IsPermitted",

        // Reading a secret back off the token under the export rule.
        "KeyMaterial.ReadBackFailures",
        "KeyMaterial.ReadBackFailures..ctor",
        "KeyMaterial.ReadBackFailures.get_KdfOutput",
        "KeyMaterial.SecretReadBack",
        "KeyMaterial.SecretReadBack.Read",
        "Pkcs11Session.BeginReadBack",

        // Key operations the public API does not offer.
        "Mechanism.get_Parameters",
        "Pkcs11Key.ReadEcCurve",
        "Pkcs11Key.SignPkcs1Digest",
        "Pkcs11Key.SupportsMechanism",
        "Pkcs11Key.VerifyPkcs1Digest",

        // A module quirk MLKemPkcs11 detects and records on the library.
        "Pkcs11Library.get_MlKemDecapsulateOmitsValueLen",
        "Pkcs11Library.set_MlKemDecapsulateOmitsValueLen",

        // Shared helpers.
        "Exceptions.Pkcs11Exception.Create",
        "KeyMaterial.PostQuantumParameterSets",
        "KeyMaterial.PostQuantumParameterSets.AlgorithmOf",
        "KeyMaterial.PostQuantumParameterSets.Describe",
        "KeyMaterial.PostQuantumParameterSets.KeyTypeOf",
        "SecurePassword..ctor",
    ];

    [Fact]
    public void Algorithms_ReachesNoNonPublicMemberBeyondTheKnownOnes()
    {
        string[] added = [.. NonPublicReferences(Layer).Except(Known, StringComparer.Ordinal)];
        Assert.True(added.Length == 0,
            "Algorithms reaches a non-public member outside its namespace; use the public API instead:\n"
            + string.Join("\n", added));
    }

    [Fact]
    public void Known_ListsOnlyWhatAlgorithmsStillReaches()
    {
        string[] stale = [.. Known.Except(NonPublicReferences(Layer), StringComparer.Ordinal)];
        Assert.True(stale.Length == 0,
            "Algorithms no longer reaches these; remove them from Known:\n" + string.Join("\n", stale));
    }
}
