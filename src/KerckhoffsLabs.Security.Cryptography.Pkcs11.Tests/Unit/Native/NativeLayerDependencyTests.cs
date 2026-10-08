using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.LayerDependencies;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// The Native layer sits just above <c>Common</c>: it mirrors the C ABI and owns the module, and the rest
/// of the library is built on it. It may use the shared vocabulary (<c>Common</c>, <c>Exceptions</c>,
/// <c>Logging</c>) but nothing above it: not <c>Internal</c>, not the mechanism-parameter classes, not the
/// public façade.
/// </summary>
public sealed class NativeLayerDependencyTests
{
    private static readonly string[] Allowed = [$"{Root}.Common", $"{Root}.Exceptions", $"{Root}.Logging"];

    [Fact]
    public void NativeTypes_DependOnlyOnNativeAndTheSharedVocabulary()
    {
        string[] violations = Violations($"{Root}.Native", Allowed);
        Assert.True(violations.Length == 0, "Native depends on a higher layer:\n" + string.Join("\n", violations));
    }

    // Guards the scan itself: a reference only a method body makes is still found, so an empty list
    // above means "no dependency", not "the scanner stopped looking".
    [Fact]
    public void Scan_FindsAReferenceMadeOnlyInAMethodBody()
        => Assert.Contains(typeof(UnmanagedMemory), ReferencedTypes(typeof(MechanismParameterScope)));

    [Theory]
    [InlineData(typeof(Pkcs11Library), true)]
    [InlineData(typeof(KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.ObjectHandle), true)]
    [InlineData(typeof(KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams.CkmAesGcmParams), true)]
    [InlineData(typeof(CK_ATTRIBUTE), false)]
    [InlineData(typeof(KerckhoffsLabs.Security.Cryptography.Pkcs11.Common.CKR), false)]
    [InlineData(typeof(string), false)]
    public void Predicate_RecognisesTheLayers(Type type, bool above)
        => Assert.Equal(above, IsOutside(type, [$"{Root}.Native", .. Allowed]));
}
