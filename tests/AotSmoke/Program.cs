// Native AOT smoke test. Publishing this at all is half the value — it catches trim/reflection/AOT
// incompatibilities in the wrapper — and running it proves the interop layer actually works once
// AOT-compiled, which a publish alone does not.
//
// Two modes, because the library has two ways in and they fail differently:
//   dynamic <path>  loads a module with dlopen/LoadLibrary, the ordinary case.
//   static          binds a module linked into this executable, resolved through the entry-point
//                   module's symbol table. Only meaningful when published with
//                   -p:StaticMockArchive=<libpkcs11-mock.a>, which links the module in and exports
//                   its bootstrap symbol; without that the mode reports what is missing.
using KerckhoffsLabs.Security.Cryptography.Pkcs11;

if (args.Length == 0)
{
    Console.Error.WriteLine("Usage: AotSmoke <path-to-pkcs11-library>");
    Console.Error.WriteLine("       AotSmoke static");
    return 2;
}

try
{
    if (string.Equals(args[0], "static", StringComparison.Ordinal))
    {
#if STATIC_MOCK_LINKED
        using var lib = Pkcs11Library.LoadStaticallyLinked();
        Report("static", lib.GetInfo());
        return 0;
#else
        Console.Error.WriteLine(
            "static mode requires publishing with -p:StaticMockArchive=<path to libpkcs11-mock.a>.");
        return 2;
#endif
    }

    using var dynamicLib = new Pkcs11Library(args[0]);
    Report("dynamic", dynamicLib.GetInfo());
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"{ex.GetType().Name}: {ex.Message}");
    return 1;
}

static void Report(string mode, LibraryInfo info)
{
    Console.WriteLine($"mode={mode}");
    Console.WriteLine($"manufacturer={info.ManufacturerId}");
    Console.WriteLine($"cryptoki={info.CryptokiVersion}");
}
