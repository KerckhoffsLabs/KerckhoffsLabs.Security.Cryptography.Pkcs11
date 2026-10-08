using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.LayerDependencies;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Common;

/// <summary>
/// <c>Common</c> is the bottom layer: the public PKCS#11 constants every other layer speaks. It depends
/// on nothing else in this library, so a constant never drags the marshalling layer or the façade along.
/// </summary>
public sealed class CommonLayerDependencyTests
{
    [Fact]
    public void CommonTypes_DependOnNothingElseInTheLibrary()
    {
        string[] violations = Violations($"{Root}.Common");
        Assert.True(violations.Length == 0, "Common depends on another layer:\n" + string.Join("\n", violations));
    }

    // Guards the scan: the one Common member computed at run time is still scanned, so an empty list
    // above means "no dependency", not "nothing was looked at".
    [Fact]
    public void Scan_SeesTheRuntimeSentinelsInitializer()
        => Assert.Contains(typeof(KerckhoffsLabs.Runtime.InteropServices.NativeCULong), ReferencedTypes(typeof(CK)));
}
