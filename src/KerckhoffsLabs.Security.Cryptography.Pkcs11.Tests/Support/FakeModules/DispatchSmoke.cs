using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

/// <summary>
/// One call of one <see cref="LowLevelPkcs11Library"/> wrapper, for the per-family dispatch smoke tests:
/// <paramref name="Invoke"/> makes the call on session <see cref="DispatchSmoke.Session"/> and returns its result.
/// </summary>
internal sealed record DispatchCase(string Function, Func<LowLevelPkcs11Library, CKR> Invoke);

/// <summary>
/// The three things every wrapper must do, checked through the real function table: reach the module when
/// it provides the function, report <c>CKR_FUNCTION_NOT_SUPPORTED</c> without calling anything when its
/// slot is NULL, and refuse a call after dispose without reaching the module.
/// </summary>
internal static class DispatchSmoke
{
    /// <summary>The session handle every case calls on. It encodes no instance, so it reaches the active module.</summary>
    public static readonly NativeCULong Session = (NativeCULong)7;

    /// <summary>Calls <paramref name="call"/> on <paramref name="module"/>, which implements it, and returns what it returned.</summary>
    public static CKR ReachesTheModule(FakeModule module, DispatchCase call)
    {
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        CKR rv = call.Invoke(lowLevel);

        Assert.Equal(1, module.CallCount(call.Function));
        return rv;
    }

    public static void ReportsAMissingFunctionUnsupported(DispatchCase call)
    {
        using var module = new EmptyModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, call.Invoke(lowLevel));
        Assert.Equal(0, module.CallCount(call.Function));
    }

    public static void RefusesACallAfterDispose(FakeModule module, DispatchCase call)
    {
        LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        lowLevel.Dispose();

        Assert.Throws<ObjectDisposedException>(() => call.Invoke(lowLevel));
        Assert.Equal(0, module.CallCount(call.Function));
    }

    /// <summary>A v2.40 module that provides nothing beyond <c>C_Initialize</c> and <c>C_Finalize</c>.</summary>
    private sealed class EmptyModule : FakeModule;
}
