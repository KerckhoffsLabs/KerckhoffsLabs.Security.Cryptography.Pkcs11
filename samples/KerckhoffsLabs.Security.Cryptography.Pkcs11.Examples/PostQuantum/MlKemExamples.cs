using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/ml-kem.md: ML-KEM (FIPS 203), decapsulating into a token key.</summary>
public static class MlKemExamples
{
    public static byte[] GenerateMlKemKey(string modulePath, string tokenLabel, SecurePin pin, string keyLabel)
    {
        #region GenerateMlKemKey
        // 1. Load the module and log in. The module path and token label come from configuration; the PIN
        //    from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

        // 2. Generate an ML-KEM-768 key pair on the token. No helper generates one, so the templates name the
        //    parameter set and give each half one role: encapsulate for the public half, decapsulate for the
        //    private one. Both halves are token objects (OnToken: CKA_TOKEN), which stay on the token when
        //    the session closes, and carry keyLabel as CKA_LABEL and the same random CKA_ID, which ties the
        //    halves together; the application opens the pair by either. Pick a label no other key on the
        //    token has, as OpenKey refuses an ambiguous one. ForPrivateKey starts sensitive (CKA_SENSITIVE:
        //    never revealed) and non-extractable (CKA_EXTRACTABLE false: it cannot be wrapped off the token),
        //    with every role off.
        byte[] id = RandomNumberGenerator.GetBytes(16);
        using ObjectTemplate publicTemplate = ObjectTemplate.ForPublicKey(CKK.CKK_ML_KEM)
            .Label(keyLabel)
            .Id(id)
            .OnToken()
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)CkpMlKem.CKP_ML_KEM_768)
            .Attribute(CKA.CKA_ENCAPSULATE, true)
            .Build();
        using ObjectTemplate privateTemplate = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_KEM)
            .Label(keyLabel)
            .Id(id)
            .OnToken()
            .Attribute(CKA.CKA_DECAPSULATE, true)
            .Build();
        using Pkcs11Key key = session.GenerateKeyPair(
            new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN), publicTemplate, privateTemplate);

        // 3. Export the public half, the encapsulation key, to publish to senders.
        using var mlKem = new MLKemPkcs11(key);
        byte[] publicKey = mlKem.ExportEncapsulationKey();
        // 4. The using declarations dispose the adapter, the key handle, the session and the library. The key
        //    pair stays on the token.
        #endregion
        return publicKey;
    }

    public static byte[] MlKemReceiveAesKey(string modulePath, string tokenLabel, SecurePin pin, string keyLabel, byte[] message)
    {
        #region MlKemReceiveAesKey
        // 1. Load the module and log in. The module path and token label come from configuration; the
        //    PIN from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

        // 2. The receiver: open its ML-KEM key pair, already on the token, by its CKA_LABEL (or by its
        //    CKA_ID). Both halves carry them, so OpenKey returns the pair.
        using Pkcs11Key receiver = session.OpenKey(keyLabel);
        using var mlKem = new MLKemPkcs11(receiver);            // an MLKem
        byte[] encapsulationKey = mlKem.ExportEncapsulationKey(); // what senders were given

        // 3. The sender: any ML-KEM implementation, here the BCL's. It gets a 32-byte shared secret and a
        //    ciphertext, encrypts its message under the secret, and sends both ciphertexts.
        using MLKem sender = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, encapsulationKey);
        sender.Encapsulate(out byte[] kemCiphertext, out byte[] senderSecret);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = new byte[message.Length], tag = new byte[16];
        using (var senderAesGcm = new AesGcm(senderSecret, tagSizeInBytes: 16))
            senderAesGcm.Encrypt(nonce, message, ciphertext, tag);
        CryptographicOperations.ZeroMemory(senderSecret); // the sender's secret is bytes in its process

        // 4. The receiver decapsulates on the token, straight into an AES-256 key (a session object): the
        //    shared secret never leaves the token. Then it decrypts the message with that key.
        using ObjectTemplate aesKey = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Encrypt()
            .Decrypt()
            .Build();
        using Pkcs11Key tokenKey = receiver.DecapsulateKey(new Mechanism(CKM.CKM_ML_KEM), kemCiphertext, aesKey);
        using var aesGcm = new AesGcmPkcs11(tokenKey, tagSizeInBytes: 16);
        byte[] received = new byte[ciphertext.Length];
        aesGcm.Decrypt(nonce, ciphertext, tag, received);
        // 5. The using declarations dispose the adapters, the AES key, the key-pair handle (the pair stays
        //    on the token), the session and the library, in reverse order.
        #endregion
        return received;
    }

    public static (byte[] ReceiverSecret, byte[] SenderSecret) BclMlKemReceive()
    {
        #region BclMlKemReceive
        // The receiver in software, where MLKem.IsSupported (OpenSSL 3.5 or later on Linux): its
        // decapsulation key and the shared secret are in your process.
        using MLKem receiver = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        byte[] encapsulationKey = receiver.ExportEncapsulationKey(); // published to senders

        // The sender, as on the PKCS#11 tab.
        using MLKem sender = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, encapsulationKey);
        sender.Encapsulate(out byte[] ciphertext, out byte[] senderSecret);

        // The receiver recovers the 32-byte shared secret, to use as an AES-256 key.
        byte[] receiverSecret = receiver.Decapsulate(ciphertext);
        #endregion
        return (receiverSecret, senderSecret);
    }
}
