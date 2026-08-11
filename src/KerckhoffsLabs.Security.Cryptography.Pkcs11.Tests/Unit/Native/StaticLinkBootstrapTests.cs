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

    // The test host does not export a cryptoki bootstrap, so this is the "you asked for the static
    // path but did not link the module in" diagnostic. Reaching it at all is the point: the old code
    // failed earlier and for the wrong reason, with a DllNotFoundException for a library literally
    // named "__Internal".
    [Fact]
    public void LoadStaticallyLinked_WhenTheHostExportsNoBootstrap_ThrowsEntryPointNotFound()
    {
        var ex = Assert.Throws<EntryPointNotFoundException>(Pkcs11Library.LoadStaticallyLinked);

        Assert.Contains("C_GetFunctionList", ex.Message, StringComparison.Ordinal);
    }
}
