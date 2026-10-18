using System.Runtime.CompilerServices;
using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.LayerDependencies;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Architecture;

/// <summary>
/// The root namespace is the public façade. An internal helper there would be reachable from every layer
/// that may use the façade (<c>Algorithms</c>, <c>KeyMaterial</c>) without any layering test noticing, so
/// internal code goes in a namespace of its own: <c>KeyMaterial</c> for helpers <c>Algorithms</c> needs,
/// <c>Internal</c> for the rest.
/// </summary>
public sealed class RootNamespaceTests
{
    [Fact]
    public void EveryTopLevelTypeInTheRootNamespace_IsPublic()
    {
        string[] internalTypes = [.. typeof(Pkcs11Library).Assembly.GetTypes()
            .Where(t => t.Namespace == Root && !t.IsNested && !t.IsPublic)
            .Where(t => !t.IsDefined(typeof(CompilerGeneratedAttribute), inherit: false))
            .Select(t => t.FullName!)
            .Order(StringComparer.Ordinal)];

        Assert.True(internalTypes.Length == 0,
            "Internal types in the public root namespace; move them to KeyMaterial or Internal:\n" + string.Join("\n", internalTypes));
    }
}
