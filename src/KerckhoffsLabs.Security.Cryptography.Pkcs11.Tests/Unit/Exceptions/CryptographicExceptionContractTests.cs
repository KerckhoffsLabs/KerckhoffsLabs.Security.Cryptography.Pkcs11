using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

// Deliberately drives the AllowInsecure-gated PKCS#1 v1.5 path: the refusal is what is being caught.
#pragma warning disable KLPKCS11008

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Exceptions;

/// <summary>
/// The façades in <c>Algorithms</c> are documented as drop-in substitutes for their BCL base types,
/// so callers hold them as <c>RSA</c>, <c>ECDsa</c>, <c>MLDsa</c> or <c>HMAC</c> and handle failures
/// the way every consumer of those types does — <c>catch (CryptographicException)</c>, often in
/// generic wrapper code that has never heard of PKCS#11. An exception escaping such a call from
/// outside that hierarchy would slip past the caller's error handling entirely. These tests hold the
/// library to that contract from the caller's side, through the BCL-typed reference.
/// </summary>
public sealed class CryptographicExceptionContractTests
{
    // Note the ThrowsAny: xUnit's Assert.Throws<T> demands an *exact* type match, so it would reject
    // the derived types even though the catch clause a consumer writes accepts them. ThrowsAny has
    // the same assignability semantics as `catch`, which is the behaviour under test.

    [Fact]
    public void SecurityRefusal_FromABclTypedCall_IsCaughtAsCryptographicException()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var key = workspace.GenerateRsaKeyPair(modulusBits: 2048);

        // Held as the BCL base type, exactly as a consumer substituting this for an RSA would.
        using RSA rsa = new RSAPkcs11(key);

        var ex = Assert.ThrowsAny<CryptographicException>(
            () => rsa.Encrypt("nope"u8.ToArray(), RSAEncryptionPadding.Pkcs1));

        // Still the specific type, with its detail intact — the base class is added, not substituted.
        var insecure = Assert.IsType<InsecureOperationException>(ex);
        Assert.Equal(CKM.CKM_RSA_PKCS, insecure.Mechanism);
    }

    [Fact]
    public void TokenFailure_FromABclTypedCall_IsCaughtAsCryptographicException()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var key = workspace.GenerateRsaKeyPair(modulusBits: 2048);
        using RSA rsa = new RSAPkcs11(key);

        byte[] ciphertext = rsa.Encrypt(RandomNumberGenerator.GetBytes(32), RSAEncryptionPadding.OaepSHA256);
        ciphertext[0] ^= 0xFF;

        var ex = Assert.ThrowsAny<CryptographicException>(
            () => rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256));

        // The CKR and failing method survive the reparenting — a caller that does know about PKCS#11
        // can still narrow to Pkcs11Exception and read them.
        var pkcs11 = Assert.IsAssignableFrom<Pkcs11Exception>(ex);
        Assert.Equal(CKR.CKR_ENCRYPTED_DATA_INVALID, pkcs11.ReturnValue);
        Assert.False(string.IsNullOrEmpty(pkcs11.Method));
    }

    /// <summary>
    /// The general rule behind the two cases above. A newly added exception type that sits outside
    /// <see cref="CryptographicException"/> reintroduces the defect for whichever call path raises
    /// it, and would otherwise be found only by the consumer it escapes past.
    /// </summary>
    [Fact]
    public void EveryPublicExceptionType_DerivesFromCryptographicException()
    {
        var exceptionTypes = typeof(Pkcs11Library).Assembly.GetExportedTypes()
            .Where(t => typeof(Exception).IsAssignableFrom(t))
            .ToList();

        // Non-vacuity: the library really does export the hierarchy this is checking.
        Assert.Contains(typeof(Pkcs11Exception), exceptionTypes);
        Assert.True(exceptionTypes.Count >= 4, $"Expected the exception surface, found {exceptionTypes.Count}.");

        var offenders = exceptionTypes
            .Where(t => !typeof(CryptographicException).IsAssignableFrom(t))
            .Select(t => t.FullName!)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        Assert.Empty(offenders);
    }
}
