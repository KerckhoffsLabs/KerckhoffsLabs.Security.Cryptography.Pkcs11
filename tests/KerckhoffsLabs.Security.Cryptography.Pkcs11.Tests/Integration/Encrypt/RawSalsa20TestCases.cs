using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// Raw CKM_SALSA20 is refused under SecureOnly (no integrity protection); it is the mechanism under test.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>
/// Backend-agnostic known-answer tests for raw <c>CKM_SALSA20</c> with <see cref="CkmSalsa20Params"/>
/// (256-bit key, 64-bit nonce). The expected keystreams come from an independent
/// implementation: the eSTREAM 256-bit set 1 vector 0, and a two-block vector computed with
/// PyCryptodome 3.23.0, whose Salsa20 reproduces that eSTREAM vector. The session runs under
/// <see cref="CryptoPolicy.AllowInsecure"/>, since SecureOnly refuses raw Salsa20.
/// </summary>
internal static class RawSalsa20TestCases
{
    private static readonly byte[] TwoBlockKey = [.. Enumerable.Range(0, 32).Select(i => (byte)i)];
    private static readonly byte[] TwoBlockNonce = Convert.FromHexString("0001020304050607");
    private static readonly byte[] TwoBlockPlaintext =
        "Salsa20 keystream known answer, two blocks long so the block counter moves past zero........ok!!"u8.ToArray();
    private static readonly byte[] TwoBlockCiphertext = Convert.FromHexString(
        "7dcc632c796519eebd17cada5c96319642fb2fc614ebb6f2788a9f63cb8bea9c03c86a5f3435b816533bd8bf9118fb85" +
        "8eb725092e5749f2899e5589dcd4d409cf4e4e2bf96914fbdbca1eb4d6ff9585e1a7620b3d36e2e047631ed1eeb98ec6");

    internal static void Assert_Estream_Set1Vector0_Keystream(IPkcs11Backend backend)
    {
        byte[] key = [0x80, .. new byte[31]];
        byte[] keystream = Convert.FromHexString(
            "E3BE8FDD8BECA2E3EA8EF9475B29A6E7003951E1097A5C38D23B7A5FAD9F6844" +
            "B22C97559E2723C7CBBD3FE4FC8D9A0744652A83E72A9C461876AF4D7EF1A117");

        Assert.Equal(Convert.ToHexString(keystream), Convert.ToHexString(Encrypt(backend, key, new byte[8], new byte[64])));
    }

    internal static void Assert_TwoBlockMessage_MatchesReference_AndRoundTrips(IPkcs11Backend backend)
    {
        byte[] ciphertext = Encrypt(backend, TwoBlockKey, TwoBlockNonce, TwoBlockPlaintext);

        Assert.Equal(Convert.ToHexString(TwoBlockCiphertext), Convert.ToHexString(ciphertext));
        Assert.Equal(TwoBlockPlaintext, Decrypt(backend, TwoBlockKey, TwoBlockNonce, ciphertext));
    }

    // The two-block message's second block, encrypted on its own from block counter 1, is the reference's
    // second block: the counter is where the keystream starts, not refused or ignored.
    internal static void Assert_NonZeroBlockCounter_StartsTheKeystreamThere(IPkcs11Backend backend)
    {
        byte[] ciphertext = Encrypt(backend, TwoBlockKey, TwoBlockNonce, TwoBlockPlaintext[64..], blockCounter: 1);

        Assert.Equal(Convert.ToHexString(TwoBlockCiphertext[64..]), Convert.ToHexString(ciphertext));
        Assert.Equal(TwoBlockPlaintext[64..], Decrypt(backend, TwoBlockKey, TwoBlockNonce, ciphertext, blockCounter: 1));
    }

    private static byte[] Encrypt(IPkcs11Backend backend, byte[] key, byte[] nonce, byte[] data, ulong blockCounter = 0) =>
        WithKey(backend, key, k => k.Encrypt(Salsa20(nonce, blockCounter), data));

    private static byte[] Decrypt(IPkcs11Backend backend, byte[] key, byte[] nonce, byte[] data, ulong blockCounter = 0) =>
        WithKey(backend, key, k => k.Decrypt(Salsa20(nonce, blockCounter), data));

    // CK_SALSA20_PARAMS: a little-endian 64-bit block counter.
    private static Mechanism Salsa20(byte[] nonce, ulong blockCounter) =>
        new(CKM.CKM_SALSA20, new CkmSalsa20Params(BitConverter.GetBytes(blockCounter), nonce, 64));

    private static byte[] WithKey(IPkcs11Backend backend, byte[] value, Func<Pkcs11Key, byte[]> body)
    {
        backend.RequireMechanism(CKM.CKM_SALSA20);
        using var session = backend.OpenSession();
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_SALSA20)
            .Label($"kl-salsa20-{Guid.NewGuid():N}").Value(value).Encrypt().Decrypt().OnToken(backend.SupportsTokenObjects).Build();
        using var key = session.ImportKey(template);
        try { return body(key); }
        finally { key.Destroy(); }
    }
}
