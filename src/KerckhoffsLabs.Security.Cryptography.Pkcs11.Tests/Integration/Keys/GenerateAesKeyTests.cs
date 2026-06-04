using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

internal static class GenerateAesKeyTestCases
{
    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.Library.OpenWorkspace(backend.TokenLabel, CKU.CKU_USER, new SecurePin(backend.UserPin.Span));

    internal static void Assert_RejectsWrongBitLength(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        Assert.Throws<ArgumentOutOfRangeException>(() => workspace.GenerateAesKey(bitLength: 64));
        Assert.Throws<ArgumentOutOfRangeException>(() => workspace.GenerateAesKey(bitLength: 100));
        Assert.Throws<ArgumentOutOfRangeException>(() => workspace.GenerateAesKey(bitLength: 512));
    }

    internal static void Assert_GeneratesAes256Key(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        using var key = workspace.GenerateAesKey(bitLength: 256);

        Assert.False(key.PrivateHandle.IsInvalid);

        var attrs = workspace.Session.GetAttributeValue(key.PrivateHandle, [CKA.CKA_VALUE_LEN]);
        try
        {
            Assert.Single(attrs);
            Assert.Equal(32UL, attrs[0].GetValueAsUlong());
        }
        finally
        {
            foreach (var a in attrs) a.Dispose();
        }
    }
}

[Collection("Mock")]
public sealed class GenerateAesKeyTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void RejectsWrongBitLength() => GenerateAesKeyTestCases.Assert_RejectsWrongBitLength(_backend);
}

[Collection("SoftHsm")]
public sealed class GenerateAesKeyTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RejectsWrongBitLength() => GenerateAesKeyTestCases.Assert_RejectsWrongBitLength(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GeneratesAes256Key() => GenerateAesKeyTestCases.Assert_GeneratesAes256Key(_backend);
}
