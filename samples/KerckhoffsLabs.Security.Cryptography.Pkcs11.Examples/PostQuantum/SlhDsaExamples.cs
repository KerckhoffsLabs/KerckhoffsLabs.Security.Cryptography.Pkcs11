using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/slh-dsa.md: SLH-DSA (FIPS 205) signatures with a token key.</summary>
public static class SlhDsaExamples
{
    public static byte[] GenerateSlhDsaKey(string modulePath, string tokenLabel, SecurePin pin, string keyLabel)
    {
        #region GenerateSlhDsaKey
        // 1. Load the module and log in. The module path and token label come from configuration; the PIN
        //    from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

        // 2. Generate an SLH-DSA-SHA2-128s key pair on the token. No helper generates one, so the templates
        //    name the parameter set and give each half one role: verify for the public half, sign for the
        //    private one. Both halves are token objects (OnToken: CKA_TOKEN), which stay on the token when
        //    the session closes, and carry keyLabel as CKA_LABEL and the same random CKA_ID, which ties the
        //    halves together; the application opens the pair by either. Pick a label no other key on the
        //    token has, as OpenKey refuses an ambiguous one. ForPrivateKey starts sensitive (CKA_SENSITIVE:
        //    never revealed) and non-extractable (CKA_EXTRACTABLE false: it cannot be wrapped off the token),
        //    with every role off.
        byte[] id = RandomNumberGenerator.GetBytes(16);
        using ObjectTemplate publicTemplate = ObjectTemplate.ForPublicKey(CKK.CKK_SLH_DSA)
            .Label(keyLabel)
            .Id(id)
            .OnToken()
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHA2_128S)
            .Verify()
            .Build();
        using ObjectTemplate privateTemplate = ObjectTemplate.ForPrivateKey(CKK.CKK_SLH_DSA)
            .Label(keyLabel)
            .Id(id)
            .OnToken()
            .Sign()
            .Build();
        using Pkcs11Key key = session.GenerateKeyPair(
            new Mechanism(CKM.CKM_SLH_DSA_KEY_PAIR_GEN), publicTemplate, privateTemplate);

        // 3. Export the public half, for those who verify the signatures.
#pragma warning disable SYSLIB5006 // SlhDsaPkcs11 is [Experimental] in .NET 10
        using var slhDsa = new SlhDsaPkcs11(key);
        byte[] publicKey = slhDsa.ExportSlhDsaPublicKey();
#pragma warning restore SYSLIB5006
        // 4. The using declarations dispose the adapter, the key handle, the session and the library. The key
        //    pair stays on the token.
        #endregion
        return publicKey;
    }

    public static (byte[] Signature, byte[] PublicKey) SlhDsaSign(
        string modulePath, string tokenLabel, SecurePin pin, string keyLabel, byte[] data)
    {
        #region SlhDsaSign
        // SlhDsa and its adapter are [Experimental] in .NET 10 (SYSLIB5006): the API may still change.
#pragma warning disable SYSLIB5006
        // 1. Load the module and log in. The module path and token label come from configuration; the
        //    PIN from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

        // 2. Open the SLH-DSA key pair that is already on the token, by its CKA_LABEL (or by its CKA_ID).
        //    Both halves carry them, so OpenKey returns the pair.
        using Pkcs11Key key = session.OpenKey(keyLabel);
        using var slhDsa = new SlhDsaPkcs11(key);               // an SlhDsa

        // 3. Sign on the token, and export the public key for verifiers.
        byte[] signature = slhDsa.SignData(data);               // small "s" sets: slow to sign, small signatures
        byte[] publicKey = slhDsa.ExportSlhDsaPublicKey();
#pragma warning restore SYSLIB5006
        // 4. The using declarations dispose the adapter, the key handle (the pair stays on the token),
        //    the session and the library, in reverse order.
        #endregion
        return (signature, publicKey);
    }

    public static (byte[] Signature, byte[] PublicKey) BclSlhDsaSign(byte[] data)
    {
        #region BclSlhDsaSign
        // In software, where SlhDsa.IsSupported (OpenSSL 3.5 or later on Linux). The private key is in your process.
#pragma warning disable SYSLIB5006
        using SlhDsa slhDsa = SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_128s);

        byte[] signature = slhDsa.SignData(data);
        byte[] publicKey = slhDsa.ExportSlhDsaPublicKey();
#pragma warning restore SYSLIB5006
        #endregion
        return (signature, publicKey);
    }
}
