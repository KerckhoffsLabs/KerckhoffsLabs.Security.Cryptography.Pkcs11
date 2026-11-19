namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

// The test-side HChaCha20 the XChaCha20 counter vectors are run through. A wrong subkey would fail those cases on every
// backend at once, so it is checked on its own here, against draft-irtf-cfrg-xchacha-03 §2.2.1.
public sealed class HChaCha20Tests
{
    [Fact]
    public void DeriveSubkey_MatchesTheDraftsTestVector()
    {
        byte[] key = [.. Enumerable.Range(0, 32).Select(i => (byte)i)];
        byte[] nonce = Convert.FromHexString("000000090000004a0000000031415927");

        Assert.Equal(
            Convert.FromHexString("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"),
            HChaCha20.DeriveSubkey(key, nonce));
    }
}
