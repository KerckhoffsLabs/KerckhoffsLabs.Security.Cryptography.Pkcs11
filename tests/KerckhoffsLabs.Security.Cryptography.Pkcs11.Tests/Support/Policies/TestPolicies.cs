using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.BuiltIn;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Policies;

/// <summary>Policies for tests over fake modules.</summary>
internal static class TestPolicies
{
    /// <summary>
    /// <see cref="CryptoPolicy.Recommended"/>, named the same, without its key-strength rule: a session reads nothing
    /// from the module to describe a key. The default of fake sessions and libraries, whose modules mostly answer no
    /// attributes; a test of the key-strength rule passes <see cref="CryptoPolicy.Recommended"/> itself.
    /// </summary>
    public static ComposedCryptoPolicy RecommendedWithoutKeyInspection { get; } = RecommendedDefinition.Create(inspectKeys: false);
}
