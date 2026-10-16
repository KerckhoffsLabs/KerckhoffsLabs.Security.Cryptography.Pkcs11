using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.LayerDependencies;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// <c>Algorithms</c> adapts the façade to the BCL's algorithm types (<c>RSA</c>, <c>Aes</c>,
/// <c>HashAlgorithm</c>, ...), so it is built on the façade: the root namespace's types, the shared
/// vocabulary (<c>Common</c>, <c>Exceptions</c>, <c>Logging</c>), <c>KeyMaterial</c>, <c>MechanismParams</c>,
/// <c>Objects</c> and <c>Policy</c>. It never reaches past the façade into the marshalling layer, <c>Internal</c> or
/// <c>Native</c>, so that layer can change without touching the adapters, and an adapter cannot bypass
/// what the façade enforces.
/// </summary>
public sealed class AlgorithmsLayerDependencyTests
{
    private static readonly string[] Allowed =
    [
        $"{Root}.Common", $"{Root}.Exceptions", $"{Root}.KeyMaterial", $"{Root}.Logging",
        $"{Root}.MechanismParams", $"{Root}.Objects", $"{Root}.Policy",
    ];

    // The root namespace contains every layer, so only the façade's own types are allowed from it.
    private static readonly string[] AllowedExactly = [Root];

    [Fact]
    public void AlgorithmsTypes_DependOnlyOnThePublicLayers()
    {
        string[] violations = Violations($"{Root}.Algorithms", Allowed, AllowedExactly);
        Assert.True(violations.Length == 0, "Algorithms depends on a lower layer:\n" + string.Join("\n", violations));
    }

    // Guards the scan itself: a reference only a method body makes is still found, so an empty list
    // above means "no dependency", not "the scanner stopped looking".
    [Fact]
    public void Scan_FindsAReferenceMadeOnlyInAMethodBody()
        => Assert.Contains(typeof(CkmAesGcmParams), ReferencedTypes(typeof(AesGcmPkcs11)));

    [Theory]
    [InlineData(typeof(KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.ObjectHandle), true)]
    [InlineData(typeof(KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.CK_ATTRIBUTE), true)]
    [InlineData(typeof(KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams.CK_GCM_PARAMS), true)]
    [InlineData(typeof(Pkcs11Library), false)]
    [InlineData(typeof(Pkcs11Key), false)]
    [InlineData(typeof(KerckhoffsLabs.Security.Cryptography.Pkcs11.Common.CKM), false)]
    [InlineData(typeof(CkmAesGcmParams), false)]
    [InlineData(typeof(KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial.EcPointEncoding), false)]
    [InlineData(typeof(KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue.PolicyCatalogue), false)]
    [InlineData(typeof(string), false)]
    public void Predicate_RecognisesTheLayers(Type type, bool outside)
        => Assert.Equal(outside, IsOutside(type, [$"{Root}.Algorithms", .. Allowed], AllowedExactly));
}
