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
    /// Asserts an AEAD authentication failure on <paramref name="backend"/>, pinning the module's
    /// return code when the backend declares one via <see cref="IPkcs11Backend.AeadAuthFailureCode"/>.
    /// </summary>
    internal static void AssertAuthFailure(IPkcs11Backend backend, Action decrypt) =>
        AssertAuthFailure(decrypt, backend.AeadAuthFailureCode);

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
