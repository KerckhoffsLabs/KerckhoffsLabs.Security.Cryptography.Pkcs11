using KerckhoffsLabs.Security.Cryptography.Pkcs11;

if (args.Length != 1)
{
    System.Console.Error.WriteLine("Usage: AotSmoke <path-to-pkcs11-library>");
    return 1;
}

using var lib = new Pkcs11Library(args[0]);
var info = lib.GetInfo();
System.Console.WriteLine($"manufacturer={info.ManufacturerId}");
System.Console.WriteLine($"cryptoki={info.CryptokiVersion}");
return 0;
