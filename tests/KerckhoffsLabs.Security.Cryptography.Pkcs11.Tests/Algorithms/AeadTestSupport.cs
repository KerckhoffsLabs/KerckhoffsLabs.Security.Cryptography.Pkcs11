using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>Shared assertions for AEAD suites (AES-GCM/CCM, ChaCha20-Poly1305).</summary>
internal static class AeadTestSupport
{
    /// <summary>
    /// A <c>byte[]</c> Encrypt or Decrypt overload: <c>(nonce, plaintext, ciphertext, tag, associatedData)</c>
    /// or <c>(nonce, ciphertext, tag, plaintext, associatedData)</c>. Its array arguments bind a call to the
    /// array overload where there is one, and to the span overload otherwise.
    /// </summary>
    internal delegate void ArrayCall(byte[] nonce, byte[] first, byte[] second, byte[] third, byte[]? associatedData);

    /// <summary>
    /// Calls <paramref name="bcl"/> and <paramref name="adapter"/> once per argument with that argument
    /// <see langword="null"/> and the others of <paramref name="lengths"/>, and asserts each fails as the BCL
    /// does: the same exception type and <see cref="ArgumentException.ParamName"/>.
    /// </summary>
    internal static void AssertNullArgumentsFailAsBcl(int[] lengths, ArrayCall bcl, ArrayCall adapter)
    {
        for (int i = 0; i < lengths.Length; i++)
        {
            byte[]?[] args = [.. lengths.Select(n => new byte[n])];
            args[i] = null;
            Exception expected = Assert.ThrowsAny<Exception>(() => bcl(args[0]!, args[1]!, args[2]!, args[3]!, null));
            Exception actual = Assert.ThrowsAny<Exception>(() => adapter(args[0]!, args[1]!, args[2]!, args[3]!, null));
            Assert.IsType<ArgumentNullException>(expected);
            Assert.Equal(expected.GetType(), actual.GetType());
            Assert.Equal(((ArgumentException)expected).ParamName, ((ArgumentException)actual).ParamName);
        }
    }

    /// <summary>
    /// Asserts the <c>byte[]</c> overloads produce the BCL's ciphertext and tag and decrypt them, with
    /// associated data, without it (<see langword="null"/>), and with an empty array, which the BCL takes
    /// as the same as <see langword="null"/>.
    /// </summary>
    internal static void AssertArrayOverloadsMatchBcl(
        int nonceSize, int tagSize, ArrayCall bclEncrypt, ArrayCall encrypt, ArrayCall decrypt)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(nonceSize);
        byte[] plaintext = RandomNumberGenerator.GetBytes(40);
        foreach (byte[]? associatedData in new byte[]?[] { RandomNumberGenerator.GetBytes(13), null, [] })
        {
            byte[] expectedCiphertext = new byte[plaintext.Length];
            byte[] expectedTag = new byte[tagSize];
            bclEncrypt(nonce, plaintext, expectedCiphertext, expectedTag, associatedData);

            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[tagSize];
            encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            Assert.Equal(expectedCiphertext, ciphertext);
            Assert.Equal(expectedTag, tag);

            byte[] decrypted = new byte[plaintext.Length];
            decrypt(nonce, ciphertext, tag, decrypted, associatedData);
            Assert.Equal(plaintext, decrypted);
        }
    }

    /// <summary>
    /// Asserts an AEAD authentication failure for <paramref name="mechanism"/> on
    /// <paramref name="backend"/>, pinning the module's return code when the backend declares one via
    /// <see cref="IPkcs11Backend.AeadAuthFailureCode"/>. A declared code the adapters do not map (a
    /// module that reports the failure with a generic code) must surface unchanged as a
    /// <see cref="Pkcs11Exception"/>: the forgery is still rejected, just not recognisably as one.
    /// </summary>
    internal static void AssertAuthFailure(IPkcs11Backend backend, CKM mechanism, Action decrypt)
    {
        CKR? declared = backend.AeadAuthFailureCode(mechanism);
        if (declared is CKR code && !AeadDecryption.IsTagMismatch(code))
        {
            var ex = Assert.ThrowsAny<Pkcs11Exception>(decrypt);
            Assert.Equal(code, ex.ReturnValue);
            return;
        }

        AssertAuthFailure(decrypt, declared);
    }

    /// <summary>
    /// Asserts an AEAD authentication failure the way a BCL caller detects one: an
    /// <see cref="AuthenticationTagMismatchException"/> (the forgery is rejected, not silently accepted
    /// or crashed), carrying the module's <see cref="Pkcs11Exception"/> as its inner exception with a
    /// tag-failure code — exactly <paramref name="expectedCode"/> when given. Backends that do not pin
    /// a code only get "one of the tag-failure codes", since the exact code varies between
    /// implementations.
    /// </summary>
    internal static void AssertAuthFailure(Action decrypt, CKR? expectedCode)
    {
        var ex = Assert.Throws<AuthenticationTagMismatchException>(decrypt);
        var inner = Assert.IsType<Pkcs11Exception>(ex.InnerException, exactMatch: false);
        Assert.True(AeadDecryption.IsTagMismatch(inner.ReturnValue), $"Unexpected inner code {inner.ReturnValue}.");
        if (expectedCode is CKR expected)
            Assert.Equal(expected, inner.ReturnValue);
    }
}
