using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// Hermetic coverage for <see cref="LowLevelPkcs11Library"/>'s CK_ULONG width guard. The real
/// call site (<c>EnsureCkUlongWidthMatchesPlatform</c>) can never observe a mismatch in a
/// correctly-built test run — <c>actual</c> and <c>expected</c> always agree — so the throw
/// branch is only reachable by calling the extracted pure check directly with deliberately
/// mismatched values.
/// </summary>
public sealed class LowLevelPkcs11LibraryCoreTests
{
    [Fact]
    public void ThrowIfWidthMismatch_MatchingWidths_DoesNotThrow()
    {
        Assert.Null(Record.Exception(() => LowLevelPkcs11Library.ThrowIfWidthMismatch(4, 4)));
        Assert.Null(Record.Exception(() => LowLevelPkcs11Library.ThrowIfWidthMismatch(8, 8)));
    }

    [Fact]
    public void ThrowIfWidthMismatch_MismatchedWidths_ThrowsPlatformNotSupportedException()
    {
        var ex = Assert.Throws<PlatformNotSupportedException>(
            () => LowLevelPkcs11Library.ThrowIfWidthMismatch(actual: 8, expected: 4));

        Assert.Contains("8 bytes", ex.Message);
        Assert.Contains("4 bytes", ex.Message);
    }
}
