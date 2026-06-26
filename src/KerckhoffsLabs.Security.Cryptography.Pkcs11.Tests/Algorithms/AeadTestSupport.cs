using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>Shared assertions for AEAD suites (AES-GCM/CCM, ChaCha20-Poly1305).</summary>
internal static class AeadTestSupport
{
    /// <summary>
    /// Asserts an AEAD authentication failure: a <see cref="Pkcs11Exception"/> is always thrown (the
    /// forgery is rejected, not silently accepted or crashed), and — when the backend pins a specific
    /// authentication-failure code via <see cref="IPkcs11Backend.AeadAuthFailureCode"/> — that the
    /// returned <see cref="CKR"/> matches it exactly. Backends that do not pin a code only get the
    /// "some Pkcs11Exception" guarantee, since the exact code varies between implementations.
    /// </summary>
    internal static void AssertAuthFailure(IPkcs11Backend backend, Action decrypt)
    {
        var ex = Assert.ThrowsAny<Pkcs11Exception>(decrypt);
        if (backend.AeadAuthFailureCode is CKR expected)
            Assert.Equal(expected, ex.ReturnValue);
    }
}
