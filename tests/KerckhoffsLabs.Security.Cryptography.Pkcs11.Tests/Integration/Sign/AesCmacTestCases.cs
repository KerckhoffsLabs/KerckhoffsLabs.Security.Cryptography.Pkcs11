using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>
/// AES-CMAC (<c>CKM_AES_CMAC</c>) through <see cref="Pkcs11Key.Sign"/> and <see cref="Pkcs11Key.Verify"/>,
/// against the RFC 4493 §4 test vectors: the four messages (empty, one block, a partial last block and
/// four whole blocks) under the RFC's AES-128 key. The BCL has no CMAC, so the RFC is the oracle. Both
/// built-in policies approve the mechanism, and no adapter wraps it, so this is the only path a caller has.
/// </summary>
internal static class AesCmacTestCases
{
    private static readonly byte[] Key = Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c");

    private const string Message =
        "6bc1bee22e409f96e93d7e117393172a" + "ae2d8a571e03ac9c9eb76fac45af8e51" +
        "30c81c46a35ce411e5fbc1191a0a52ef" + "f69f2445df4f9b17ad2b417be66c3710";

    /// <summary>The RFC 4493 §4 examples: message length in bytes and the expected MAC.</summary>
    public static TheoryData<int, string> Rfc4493Vectors => new()
    {
        { 0, "bb1d6929e95937287fa37d129b756746" },
        { 16, "070a16b46b4d4144f79bdd9dd04a287c" },
        { 40, "dfa66747de9ae63030ca32611497c827" },
        { 64, "51f0bebf7e3b9d92fc49741779363cfe" },
    };

    /// <summary><see cref="Rfc4493Vectors"/> without the empty message, for a token that refuses to MAC one.</summary>
    public static TheoryData<int, string> Rfc4493NonEmptyVectors => new()
    {
        { 16, "070a16b46b4d4144f79bdd9dd04a287c" },
        { 40, "dfa66747de9ae63030ca32611497c827" },
        { 64, "51f0bebf7e3b9d92fc49741779363cfe" },
    };

    private static byte[] MessageOf(int length) => Convert.FromHexString(Message)[..length];

    internal static void Assert_Sign_MatchesRfc4493(IPkcs11Backend backend, int length, string expectedMac) =>
        WithCmacKey(backend, key =>
            Assert.Equal(Convert.FromHexString(expectedMac), key.Sign(new Mechanism(CKM.CKM_AES_CMAC), MessageOf(length))));

    // The RFC's MAC verifies; with its first bit flipped, or over the message with its last bit flipped,
    // it does not, and the session goes on verifying.
    internal static void Assert_Verify_AcceptsRfc4493_RejectsAlteredMac(IPkcs11Backend backend, int length, string expectedMac) =>
        WithCmacKey(backend, key =>
        {
            var cmac = new Mechanism(CKM.CKM_AES_CMAC);
            byte[] message = MessageOf(length);
            byte[] mac = Convert.FromHexString(expectedMac);

            Assert.True(key.Verify(cmac, message, mac));

            byte[] alteredMac = [.. mac];
            alteredMac[0] ^= 0x80;
            Assert.False(key.Verify(cmac, message, alteredMac));

            if (message.Length > 0)
            {
                byte[] alteredMessage = [.. message];
                alteredMessage[^1] ^= 0x01;
                Assert.False(key.Verify(cmac, alteredMessage, mac));
            }

            Assert.True(key.Verify(cmac, message, mac));
        });

    private static void WithCmacKey(IPkcs11Backend backend, Action<Pkcs11Key> body)
    {
        backend.RequireMechanism(CKM.CKM_AES_CMAC);

        using var session = backend.OpenSession();
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label($"cmac-{Guid.NewGuid():N}").Value(Key).Sign().Verify().OnToken(backend.SupportsTokenObjects).Build();
        using var key = session.ImportKey(template);
        try
        {
            body(key);
        }
        finally
        {
            try { key.Destroy(); } catch (Pkcs11Exception) { /* best-effort cleanup */ }
        }
    }
}
