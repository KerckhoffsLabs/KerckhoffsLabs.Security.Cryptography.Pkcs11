using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

/// <summary>docs/examples/ml-kem.md: ML-KEM (FIPS 203), decapsulating into a token key.</summary>
public static class MlKemExamples
{
    public static byte[] MlKemReceiveAesKey(string modulePath, string tokenLabel, SecurePin pin, byte[] message)
    {
        #region MlKemReceiveAesKey
        // 1. Load the module and log in. The module path and token label come from configuration; the
        //    PIN from your secret store (see ReadPinFromEnvironment in Getting started), never from code.
        using Pkcs11Library library = Pkcs11Library.Load(modulePath);
        using Pkcs11Session session = library.OpenSessionWithPin(tokenLabel, CKU.CKU_USER, pin);

        // 2. The receiver: an ML-KEM-768 key pair on the token. The public half (the encapsulation key)
        //    may encapsulate; the private half (the decapsulation key) may decapsulate. No helper
        //    generates ML-KEM keys, so the templates name the parameter set and the two roles. A
        //    long-term pair (.Label(...) and .OnToken() on both templates) is opened later with
        //    session.OpenKey(label).
        using ObjectTemplate publicTemplate = ObjectTemplate.ForPublicKey(CKK.CKK_ML_KEM)
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)CkpMlKem.CKP_ML_KEM_768)
            .Attribute(CKA.CKA_ENCAPSULATE, true)
            .Build();
        using ObjectTemplate privateTemplate = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_KEM)
            .Attribute(CKA.CKA_DECAPSULATE, true)
            .Build();
        using Pkcs11Key receiver = session.GenerateKeyPair(
            new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN), publicTemplate, privateTemplate);
        using var mlKem = new MLKemPkcs11(receiver);            // an MLKem
        byte[] encapsulationKey = mlKem.ExportEncapsulationKey(); // published to senders

        // 3. The sender: any ML-KEM implementation, here the BCL's. It gets a 32-byte shared secret and a
        //    ciphertext, encrypts its message under the secret, and sends both ciphertexts.
        using MLKem sender = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, encapsulationKey);
        sender.Encapsulate(out byte[] kemCiphertext, out byte[] senderSecret);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = new byte[message.Length], tag = new byte[16];
        using (var senderAesGcm = new AesGcm(senderSecret, tagSizeInBytes: 16))
            senderAesGcm.Encrypt(nonce, message, ciphertext, tag);

        // 4. The receiver decapsulates on the token, straight into an AES-256 key: the shared secret
        //    never leaves the token. Then it decrypts the message with that key.
        using ObjectTemplate aesKey = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Encrypt()
            .Decrypt()
            .Build();
        using Pkcs11Key tokenKey = receiver.DecapsulateKey(new Mechanism(CKM.CKM_ML_KEM), kemCiphertext, aesKey);
        using var aesGcm = new AesGcmPkcs11(tokenKey, tagSizeInBytes: 16);
        byte[] received = new byte[ciphertext.Length];
        aesGcm.Decrypt(nonce, ciphertext, tag, received);
        // 5. The using declarations dispose the adapters, the keys (session objects: gone with the
        //    session), the session and the library, in reverse order.
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
