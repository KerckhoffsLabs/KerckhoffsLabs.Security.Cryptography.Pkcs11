// Native AOT smoke test. Publishing this at all is half the value — it catches trim/reflection/AOT
// incompatibilities in the wrapper — and running it proves the interop layer actually works once
// AOT-compiled, which a publish alone does not.
//
// Two modes, because the library has two ways in and they fail differently:
//   <path>  loads a module with dlopen/LoadLibrary, the ordinary case.
//   static  binds a module linked into this executable through LoadStaticallyLinked; needs the
//           -p:StaticMockArchive publish described in AotSmoke.csproj.
//
// With PKCS11_SMOKE_TOKEN_LABEL and PKCS11_SMOKE_USER_PIN set, the dynamic mode also drives a session
// on that token through the code that only runs once a token is in use: attribute templates (key
// generation and search), the multi-pass attribute read, a mechanism with a parameter struct
// (RSA-PSS), a digest, and the message API when the module binds it. It needs a real token
// (pkcs11-mock cannot answer the attribute reads), and the PIN comes from the environment so that no
// PIN is written down here.
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

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

    using var dynamicLib = Pkcs11Library.Load(args[0]);
    Report("dynamic", dynamicLib.GetInfo());

    string? token = Environment.GetEnvironmentVariable("PKCS11_SMOKE_TOKEN_LABEL");
    string? pin = Environment.GetEnvironmentVariable("PKCS11_SMOKE_USER_PIN");
    if (token is not null && pin is not null)
        RunSession(dynamicLib, token, pin);
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

static void RunSession(Pkcs11Library lib, string token, string pin)
{
    using Pkcs11Workspace workspace = lib.OpenWorkspaceWithPin(token, CKU.CKU_USER, new SecurePin(Encoding.UTF8.GetBytes(pin)));
    Console.WriteLine($"token={token}");

    // Attribute templates into C_GenerateKeyPair and C_FindObjectsInit, then the multi-pass read.
    using Pkcs11Key generated = workspace.GenerateRsaSigningKeyPair(modulusBits: 2048, label: "aot-smoke-rsa");
    using ObjectTemplate filter = ObjectTemplate.Empty()
        .Attribute(CKA.CKA_CLASS, (ulong)CKO.CKO_PRIVATE_KEY)
        .Label("aot-smoke-rsa")
        .Build();
    using ReadOnlyDisposableList<Pkcs11Key> keys = workspace.FindKeys(filter);
    Pkcs11Key key = keys.Count == 1 ? keys[0] : throw new InvalidOperationException($"expected 1 key, found {keys.Count}");
    using (ReadOnlyDisposableList<ObjectAttribute> attributes = key.GetAttributeValue(CKA.CKA_LABEL, CKA.CKA_MODULUS))
        Console.WriteLine($"label={attributes[0].GetValueAsString()} modulus-bytes={attributes[1].GetValueAsByteArray().Length}");

    // A mechanism carrying a parameter struct, the path secure defaults take (PSS, OAEP, GCM).
    var pss = new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32));
    byte[] signature = key.Sign(pss, "AotSmoke"u8);
    Console.WriteLine($"pss-signature-bytes={signature.Length}");

    byte[] digest = workspace.Digest(new Mechanism(CKM.CKM_SHA256), "AotSmoke"u8);
    Console.WriteLine($"sha256-bytes={digest.Length}");

    using Pkcs11Key aes = workspace.GenerateAesKey(256);
    try
    {
        var gcm = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);
        byte[] ciphertext = aes.MessageEncrypt(new Mechanism(CKM.CKM_AES_GCM), gcm, [], "AotSmoke"u8.ToArray());
        Console.WriteLine($"message-api=bound ciphertext-bytes={ciphertext.Length}");
    }
    catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_FUNCTION_NOT_SUPPORTED)
    {
        Console.WriteLine("message-api=not bound by this module");
    }
}
