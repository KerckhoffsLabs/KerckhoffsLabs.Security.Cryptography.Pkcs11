using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Random;

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
            session.Logout();
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
            session.Logout();
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
            session.Logout();
            session.CloseSession();
        }
    }
}

[Collection("Mock")]
public sealed class RandomTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void GenerateRandom_ProducesRequestedLength() => RandomTestCases.Assert_GenerateRandom_ProducesRequestedLength(_backend);

    // ConsecutiveCallsDiffer is SoftHsm-only — pkcs11-mock returns the same canned bytes.
    // SpanOverload_FillsBuffer is SoftHsm-only for the same reason.
}

[Collection("SoftHsm")]
public sealed class RandomTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GenerateRandom_ProducesRequestedLength() => RandomTestCases.Assert_GenerateRandom_ProducesRequestedLength(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GenerateRandom_ConsecutiveCallsDiffer() => RandomTestCases.Assert_GenerateRandom_ConsecutiveCallsDiffer(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GenerateRandom_SpanOverload_FillsBuffer() => RandomTestCases.Assert_GenerateRandom_SpanOverload_FillsBuffer(_backend);
}
