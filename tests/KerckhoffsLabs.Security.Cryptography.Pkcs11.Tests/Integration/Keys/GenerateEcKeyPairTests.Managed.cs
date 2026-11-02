using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

[Collection(FakeModuleCollection.Name)]
public sealed class GenerateEcKeyPairTests_Managed
{
    [Fact]
    public void SigningKeyPair_SignVerifyOnly()
    {
        using var backend = new ManagedBackend();
        GenerateEcKeyPairTestCases.Assert_SigningKeyPair_SignVerifyOnly(backend);
    }

    [Fact]
    public void KeyAgreementKeyPair_DeriveOnly()
    {
        using var backend = new ManagedBackend();
        GenerateEcKeyPairTestCases.Assert_KeyAgreementKeyPair_DeriveOnly(backend);
    }

    [Fact]
    public void KeyAgreementKeyPair_RejectsUnspecifiedCurve()
    {
        using var backend = new ManagedBackend();
        GenerateEcKeyPairTestCases.Assert_KeyAgreementKeyPair_RejectsUnspecifiedCurve(backend);
    }
}
