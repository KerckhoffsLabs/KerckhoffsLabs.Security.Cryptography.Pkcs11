using System.Security.Cryptography;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

// A consumer of a cryptography library nearly always has `using System.Security.Cryptography;` in
// scope. A public type here whose simple name matches one in that namespace makes every bare use of
// the name ambiguous (CS0104) the moment the consumer also imports this library — breaking even the
// documented samples. This guards the whole exported surface so a newly added type cannot
// reintroduce the clash; the curve type is named Pkcs11ECCurve for exactly this reason.
public sealed class PublicTypeNameCollisionTests
{
    [Fact]
    public void NoPublicType_SharesASimpleNameWithSystemSecurityCryptography()
    {
        // `ECCurve` resolving to the BCL type here — inside a namespace nested under the library's
        // own, with both namespaces imported — is itself the property under test.
        var bclNames = typeof(ECCurve).Assembly.GetExportedTypes()
            .Where(t => !t.IsNested && t.Namespace == "System.Security.Cryptography")
            .Select(t => t.Name)
            .ToHashSet(StringComparer.Ordinal);
        Assert.Contains("ECCurve", bclNames); // the reflection found the namespace, so the check is not vacuous

        var collisions = typeof(Pkcs11Library).Assembly.GetExportedTypes()
            .Where(t => !t.IsNested && bclNames.Contains(t.Name))
            .Select(t => t.FullName!)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        Assert.Empty(collisions);
    }
}
