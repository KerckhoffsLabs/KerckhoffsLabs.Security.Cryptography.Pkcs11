using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.LayerDependencies;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Architecture;

/// <summary>
/// <c>Algorithms</c> adapts the façade to the BCL's algorithm types, so it should be buildable by a consumer:
/// only from what the library makes public. <see cref="AlgorithmsLayerDependencyTests"/> checks the namespaces
/// it uses, not the accessibility of what it calls in them, so an <c>internal</c> member of <c>Pkcs11Key</c> or
/// <c>Pkcs11Session</c> passes that test. This one fails on any non-public type or member outside
/// <c>Algorithms</c> that it reaches.
/// </summary>
/// <remarks>
/// It cannot see constants (<c>Oids</c>, <c>DiagnosticIds</c>): the compiler copies their values into the caller.
/// </remarks>
public sealed class AlgorithmsPublicSurfaceTests
{
    private const string Layer = $"{Root}.Algorithms";

    // Never allow-list a member here: make it public, or move the work behind a public façade method, instead.
    [Fact]
    public void Algorithms_ReachesNoNonPublicMemberOutsideItsNamespace()
    {
        string[] reached = [.. NonPublicReferences(Layer)];
        Assert.True(reached.Length == 0,
            "Algorithms reaches a non-public member outside its namespace; use the public API instead:\n"
            + string.Join("\n", reached));
    }
}
