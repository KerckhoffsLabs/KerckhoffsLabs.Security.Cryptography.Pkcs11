using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>The getting-started page: from a module path to an operation on a token key.</summary>
public static class GettingStartedExamples
{
    public static SecurePin ReadPinFromEnvironment(string variableName)
    {
        #region ReadPinFromEnvironment
        // Never write a PIN in source code. Read it from your secret store; here, an environment
        // variable your deployment sets. SecurePin keeps it in a pinned buffer that is zeroed on Dispose.
        string pin = Environment.GetEnvironmentVariable(variableName)
            ?? throw new InvalidOperationException($"Set {variableName} to the token's user PIN.");
        return new SecurePin(pin);
        #endregion
    }

    public static byte[] EncryptAndDecryptWithTokenKey(string modulePath, string tokenLabel, SecurePin pin, byte[] plaintext)
    {
        #region EncryptAndDecryptWithTokenKey
        // 1. Load the vendor's PKCS#11 module (a .so, .dylib or .dll).
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);

        // 2. Find the token's slot by its label, log in as the normal user, and open a session of that
        //    login. The login belongs to the application: it stays until the login and every session
        //    opened from it are disposed. The session enforces the default Recommended crypto policy.
        Pkcs11Slot slot = library.GetSlotByTokenLabel(tokenLabel);
        using Pkcs11Login login = slot.Login(TokenUser.User, pin);
        using Pkcs11Session session = login.OpenSession();

        // 3. Generate an AES-256 key on the token: sensitive, non-extractable, encrypt/decrypt only.
        //    It is a session object, destroyed when the session closes; pass persistOnToken: true
        //    to keep it on the token.
        using Pkcs11Key key = session.GenerateAesKey(bitLength: 256, label: "getting-started");

        // 4. Use it through a BCL-shaped adapter. AesGcmPkcs11 has AesGcm's Encrypt/Decrypt; the key
        //    never leaves the token.
        using var aesGcm = new AesGcmPkcs11(key, tagSizeInBytes: 16);
        byte[] nonce = session.GenerateRandom(12);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);

        byte[] decrypted = new byte[ciphertext.Length];
        aesGcm.Decrypt(nonce, ciphertext, tag, decrypted);
        return decrypted;
        // 5. The using declarations dispose the adapter, key handle, session, login and library in
        //    reverse order: the session closes, the token is logged out once the login and its last
        //    session are gone, and the library calls C_Finalize if it was the one that initialized
        //    the module.
        #endregion
    }
}
