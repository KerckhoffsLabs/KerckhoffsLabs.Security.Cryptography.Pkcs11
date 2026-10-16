using KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;
using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.LayerDependencies;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Architecture;

/// <summary>
/// <c>KeyMaterial</c> holds the internal helpers both the façade and <c>Algorithms</c> use to read, encode
/// and check key material. <c>Algorithms</c> may use it, so it must stay on the façade's side of the line
/// too: the root namespace's own types, <c>Common</c>, <c>Exceptions</c> and <c>Objects</c>, never <c>Internal</c> or
/// <c>Native</c>. Otherwise an adapter would reach the marshalling layer through it. A helper that needs a
/// session core or a raw handle belongs in <c>Internal</c> (e.g. <c>Internal.PublicKeySynthesis</c>).
/// </summary>
public sealed class KeyMaterialLayerDependencyTests
{
    private static readonly string[] Allowed = [$"{Root}.Common", $"{Root}.Exceptions", $"{Root}.Objects"];

    // The root namespace contains every layer, so only the façade's own types are allowed from it.
    private static readonly string[] AllowedExactly = [Root];

    [Fact]
    public void KeyMaterialTypes_DependOnlyOnTheFacade()
    {
        string[] violations = Violations($"{Root}.KeyMaterial", Allowed, AllowedExactly);
        Assert.True(violations.Length == 0, "KeyMaterial depends on a lower layer:\n" + string.Join("\n", violations));
    }

    // Guards the scan: a façade type used only in a method body is still found, so an empty list above
    // means "no dependency", not "the scanner stopped looking".
    [Fact]
    public void Scan_FindsAFacadeTypeUsedInAMethodBody()
        => Assert.Contains(typeof(Pkcs11Key), ReferencedTypes(typeof(EcdhPeerValidator)));
}
