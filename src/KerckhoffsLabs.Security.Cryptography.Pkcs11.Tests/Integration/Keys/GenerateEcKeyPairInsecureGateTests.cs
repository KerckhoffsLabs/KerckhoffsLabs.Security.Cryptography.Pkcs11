using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

// GenerateEcKeyPair refuses sub-128-bit curves unless AllowInsecure is set, mirroring the
// SHA-1/DES secure-defaults gate. Runs on the in-process managed token (real keygen). P-224 is the
// weak curve used here because the BCL supports it on every platform.
public sealed class GenerateEcKeyPairInsecureGateTests
{
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

    [Fact]
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
