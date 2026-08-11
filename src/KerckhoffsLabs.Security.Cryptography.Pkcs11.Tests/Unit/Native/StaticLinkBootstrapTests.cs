using System.Reflection;
using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

// The statically-linked path used to bootstrap through [LibraryImport("__Internal")]. "__Internal"
// is a Mono-only pseudo-library: CoreCLR and Native AOT have no such special case and go looking for
// a real native library of that name, so the path could not work on any runtime this package
// targets. It now resolves C_GetFunctionList from the entry-point module's own symbol table, which
// is the same mechanism the dynamic path uses and works on both runtimes.
public sealed class StaticLinkBootstrapTests
{
    // The bootstrap was the assembly's only P/Invoke - everything else dispatches through the
    // function-pointer table read out of CK_FUNCTION_LIST. Zero is therefore the invariant to hold:
    // a new P/Invoke is the shape this defect would come back in, whatever library name it names.
    [Fact]
    public void TheAssembly_DeclaresNoPInvoke()
    {
        const BindingFlags All = BindingFlags.Public | BindingFlags.NonPublic
            | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

        var pinvokes = typeof(Pkcs11Library).Assembly.GetTypes()
            .SelectMany(t => t.GetMethods(All))
            .Where(m => m.Attributes.HasFlag(MethodAttributes.PinvokeImpl))
            .Select(m => $"{m.DeclaringType?.FullName}.{m.Name} -> "
                + (m.GetCustomAttribute<DllImportAttribute>()?.Value ?? "?"))
            .ToList();

        Assert.Empty(pinvokes);
    }

    // There is deliberately no in-process test of LoadStaticallyLinked's behaviour here. One was
    // tried and removed: it asserted that a host exporting no bootstrap gets an
    // EntryPointNotFoundException, which held on Linux and failed intermittently on macOS, where
    // dyld resolves through the entry-point module permissively enough that a module some other test
    // had already dlopened satisfied the lookup. That is not a flaky assertion to be stabilised, it
    // is an unsafe one: on the runs where it "passed" the call really did bind and C_Initialize
    // somebody else's module, and disposing the result would have called C_Finalize underneath the
    // tests still using it.
    //
    // The behaviour is covered where it can be covered honestly — the AotSmoke `static` mode in CI,
    // which links a module into the binary and runs on both Linux and macOS. That proves the path
    // works, which is the stronger claim; this file keeps the invariant that the old mechanism
    // cannot come back.
}
