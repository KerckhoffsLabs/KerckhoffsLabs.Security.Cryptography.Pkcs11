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
