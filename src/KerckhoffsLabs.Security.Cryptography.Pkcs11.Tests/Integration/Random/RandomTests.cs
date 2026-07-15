using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Random;

internal static class RandomTestCases
{
    internal static void Assert_GenerateRandom_ProducesRequestedLength(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            byte[] r = session.GenerateRandom(32);
            Assert.Equal(32, r.Length);
        }
        finally
        {
            TestKeys.LogoutIfRequired(backend, session);
            session.CloseSession();
        }
    }

    internal static void Assert_GenerateRandom_ConsecutiveCallsDiffer(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            byte[] a = session.GenerateRandom(32);
            byte[] b = session.GenerateRandom(32);
            Assert.NotEqual(a, b);
        }
        finally
        {
            TestKeys.LogoutIfRequired(backend, session);
            session.CloseSession();
        }
    }

    internal static void Assert_GenerateRandom_SpanOverload_FillsBuffer(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            Span<byte> buffer = stackalloc byte[16];
            int written = session.GenerateRandom(buffer);
            Assert.Equal(16, written);
            // At least one byte should be non-zero with overwhelming probability.
            bool anyNonZero = false;
            for (int i = 0; i < buffer.Length; i++) if (buffer[i] != 0) { anyNonZero = true; break; }
            Assert.True(anyNonZero, "GenerateRandom produced all-zero output (probability ~2^-128).");
        }
        finally
        {
            TestKeys.LogoutIfRequired(backend, session);
            session.CloseSession();
        }
    }
}
