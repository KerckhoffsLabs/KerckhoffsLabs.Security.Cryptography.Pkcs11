using System.Reflection;
using System.Reflection.Emit;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// Every native call in <see cref="LowLevelPkcs11Library"/> enters the module through one gate that takes a
/// reference on it. These tests call every <c>C_*</c> wrapper, found by reflection rather than listed, so a
/// wrapper that skips the gate fails here even if nobody remembered to test it.
/// </summary>
/// <remarks>
/// The wrappers take spans, which <see cref="MethodBase.Invoke(object, object[])"/> cannot pass, so each call
/// is emitted as a <see cref="DynamicMethod"/> with a default value for every argument, a local for each
/// <c>ref</c> or <c>out</c> one, and the result boxed.
/// </remarks>
[Collection(FakeModuleCollection.Name)]
public sealed class LowLevelPkcs11LibraryWrapperContractTests
{
    [Fact]
    public void EveryWrapper_RefusesACallAfterDispose_WithoutReachingTheModule()
    {
        using var module = new BareModule();
        LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        lowLevel.Dispose();

        string[] unexpected =
        [
            .. Wrappers()
                .Select(w => (w.Name, Error: Record.Exception(() => Invoker(w)(lowLevel))))
                .Where(r => r.Error is not ObjectDisposedException)
                .Select(r => $"{r.Name}: {r.Error?.GetType().Name ?? "no exception"}"),
        ];

        Assert.Empty(unexpected);
        Assert.Empty(CallsMadeAfterLoading(module));
    }

    /// <summary>
    /// A v2.40 module that implements nothing: every wrapper still enters the module, then returns
    /// <c>CKR_FUNCTION_NOT_SUPPORTED</c> for the absent function, the one rule for every wrapper, v2.40 and
    /// v3.x alike. Nothing reaches the module, and nothing calls through the NULL slot.
    /// </summary>
    [Fact]
    public void EveryWrapper_OfAFunctionTheModuleLacks_ReportsItUnsupported_WithoutReachingTheModule()
    {
        using var module = new BareModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        string[] unexpected =
        [
            .. Wrappers()
                // The two functions every FakeModule binds.
                .Where(w => w.Name is not (nameof(LowLevelPkcs11Library.C_Initialize) or nameof(LowLevelPkcs11Library.C_Finalize)))
                .Select(w => (w.Name, Outcome: Outcome(w, lowLevel)))
                .Where(r => !(ValidatesArgumentsFirst.Contains(r.Name) ? r.Outcome is ArgumentException : IsUnsupported(r.Outcome)))
                .Select(r => $"{r.Name}: {r.Outcome}"),
        ];

        Assert.Empty(unexpected);
        Assert.Empty(CallsMadeAfterLoading(module));
    }

    // Wrappers that refuse an invalid argument before they look for the function, so the default arguments
    // the invoker passes never get that far: C_InitToken needs a 32-byte label.
    private static readonly HashSet<string> ValidatesArgumentsFirst = [nameof(LowLevelPkcs11Library.C_InitToken)];

    // Guards the two tests above against a reflection filter that matches nothing and passes vacuously.
    [Fact]
    public void Wrappers_CoverTheWholeNativeSurface()
        => Assert.True(Wrappers().Length >= 100, $"Found only {Wrappers().Length} C_* wrappers.");

    private static MethodInfo[] Wrappers()
        => [.. typeof(LowLevelPkcs11Library)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(m => m.Name.StartsWith("C_", StringComparison.Ordinal) && !m.IsGenericMethodDefinition)
            .OrderBy(m => m.Name, StringComparer.Ordinal)];

    // What a call returned, or the exception it threw.
    private static object Outcome(MethodInfo wrapper, LowLevelPkcs11Library lowLevel)
    {
        object? result = null;
        Exception? error = Record.Exception(() => result = Invoker(wrapper)(lowLevel));
        return error ?? result ?? "returned nothing";
    }

    private static bool IsUnsupported(object outcome) => outcome is CKR.CKR_FUNCTION_NOT_SUPPORTED;

    // Loading the module calls C_GetFunctionList; nothing after that may reach it.
    private static IEnumerable<string> CallsMadeAfterLoading(FakeModule module)
        => module.Calls.Keys.Where(name => name != "C_GetFunctionList");

    /// <summary>Calls <paramref name="method"/> with a default value for every argument and returns its result, boxed.</summary>
    private static Func<LowLevelPkcs11Library, object?> Invoker(MethodInfo method)
    {
        var dynamicMethod = new DynamicMethod(
            $"Call_{method.Name}", typeof(object), [typeof(LowLevelPkcs11Library)],
            typeof(LowLevelPkcs11LibraryWrapperContractTests).Module, skipVisibility: true);
        ILGenerator il = dynamicMethod.GetILGenerator();

        il.Emit(OpCodes.Ldarg_0);
        foreach (ParameterInfo parameter in method.GetParameters())
        {
            bool byRef = parameter.ParameterType.IsByRef;
            Type type = byRef ? parameter.ParameterType.GetElementType()! : parameter.ParameterType;
            LocalBuilder local = il.DeclareLocal(type);
            il.Emit(OpCodes.Ldloca, local);
            il.Emit(OpCodes.Initobj, type);
            il.Emit(byRef ? OpCodes.Ldloca : OpCodes.Ldloc, local);
        }
        il.Emit(OpCodes.Callvirt, method);

        if (method.ReturnType == typeof(void))
            il.Emit(OpCodes.Ldnull);
        else if (method.ReturnType.IsValueType)
            il.Emit(OpCodes.Box, method.ReturnType);
        il.Emit(OpCodes.Ret);

        return dynamicMethod.CreateDelegate<Func<LowLevelPkcs11Library, object?>>();
    }

    /// <summary>A v2.40 module that overrides nothing: only <c>C_Initialize</c> and <c>C_Finalize</c> are bound.</summary>
    private sealed class BareModule : FakeModule;
}
