using System.Reflection;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.ThreadSafety;

/// <summary>
/// Regression coverage for the two-part fix to <c>LowLevelPkcs11Library.Dispose</c>: the disposed
/// flag must be set before the module is unmapped (not after), and it must be <c>volatile</c> so a
/// write on the disposing thread is guaranteed visible to a thread about to dispatch a native call
/// through <c>ObjectDisposedException.ThrowIf(_disposed, this)</c>. These tests pin the two
/// properties that make the race window as narrow as a flag can: it really is <c>volatile</c>, and
/// the guard still fires after the reorder.
/// </summary>
/// <remarks>
/// A flag narrows the window but cannot close it: a call that passed the check is still inside the
/// module when Dispose tears it down. <see cref="LibraryDisposeRaceTests"/> reproduces that
/// deterministically with a parked call; these tests stay until the fix those tests wait for replaces
/// the flag.
/// </remarks>
[Collection("Mock")]
public sealed class LowLevelPkcs11LibraryDisposeTests(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void DisposedField_IsVolatile()
    {
        FieldInfo field = typeof(LowLevelPkcs11Library).GetField("_disposed", BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new InvalidOperationException("LowLevelPkcs11Library._disposed not found — has it been renamed?");

        bool isVolatile = field.GetRequiredCustomModifiers()
            .Contains(typeof(System.Runtime.CompilerServices.IsVolatile));

        Assert.True(isVolatile,
            "_disposed must stay volatile: it is written on the disposing thread and read (via " +
            "ObjectDisposedException.ThrowIf) from every thread issuing a native call.");
    }

    [Fact]
    public void Dispose_ThenNativeCall_ThrowsObjectDisposedException()
    {
        var lib = new LowLevelPkcs11Library(_backend.LibraryPath);
        lib.Dispose();

        var info = new CK_INFO();
        Assert.Throws<ObjectDisposedException>(() => lib.C_GetInfo(ref info));
    }
}
