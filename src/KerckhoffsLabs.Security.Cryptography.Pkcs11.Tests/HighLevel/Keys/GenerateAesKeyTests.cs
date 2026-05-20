using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Keys;

internal static class GenerateAesKeyTestCases
{
    internal static void Assert_RejectsWrongBitLength(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => session.GenerateAesKey(bitLength: 64));
            Assert.Throws<ArgumentOutOfRangeException>(() => session.GenerateAesKey(bitLength: 100));
            Assert.Throws<ArgumentOutOfRangeException>(() => session.GenerateAesKey(bitLength: 512));
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }

    internal static void Assert_GeneratesAes256Key(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle key = session.GenerateAesKey(bitLength: 256);
            try
            {
                Assert.NotEqual(0UL, key.ObjectId);
                var attrs = session.GetAttributeValue(key, [CKA.CKA_VALUE_LEN]);
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
            finally
            {
                session.DestroyObject(key);
            }
        }
        finally
        {
            session.Logout();
            session.CloseSession();
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
