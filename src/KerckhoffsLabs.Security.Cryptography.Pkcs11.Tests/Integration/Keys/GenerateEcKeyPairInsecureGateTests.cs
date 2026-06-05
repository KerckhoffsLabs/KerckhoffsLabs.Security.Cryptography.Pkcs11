using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

// GenerateEcKeyPair refuses sub-128-bit curves unless AllowInsecure is set, mirroring the
// SHA-1/DES secure-defaults gate. Runs on the in-process managed token (real keygen). P-224 is the
// weak curve used here; the throws-path needs no keygen, but actually generating it needs BCL P-224
// support — macOS's SecurityFramework lacks it, so the generate case is gated on a probe.
public sealed class GenerateEcKeyPairInsecureGateTests
{
    public static bool P224Supported { get; } = ProbeP224();

    private static bool ProbeP224()
    {
        try
        {
            // BCL ECCurve.NamedCurves has no P-224 constant; build it by OID (secp224r1).
            using var e = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.CreateFromValue("1.3.132.0.33"));
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    [Fact]
    public void WeakCurve_Throws_WithoutAllowInsecure()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);

#pragma warning disable CS0618 // exercising the gate with an intentionally-obsolete weak curve
        Assert.Throws<InsecureOperationException>(
            () => workspace.GenerateEcKeyPair(ECCurve.NamedCurves.NistP224));
#pragma warning restore CS0618
    }

    [ConditionalFact(nameof(P224Supported))]
    public void WeakCurve_Generates_UnderAllowInsecureScope()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);

        using (workspace.AllowInsecureScope())
        {
#pragma warning disable CS0618
            using var key = workspace.GenerateEcKeyPair(ECCurve.NamedCurves.NistP224);
#pragma warning restore CS0618
            Assert.False(key.PrivateHandle.IsInvalid);
            Assert.False(key.PublicHandle.IsInvalid);
        }
    }

    [Fact]
    public void StrongCurve_Generates_WithoutAllowInsecure()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);

        using var key = workspace.GenerateEcKeyPair(ECCurve.NamedCurves.NistP256);
        Assert.False(key.PrivateHandle.IsInvalid);
        Assert.False(key.PublicHandle.IsInvalid);
    }
}
