using KerckhoffsLabs.Security.Cryptography.Pkcs11;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal sealed partial class Pkcs11Session
{
    /// <summary>
    /// Decrypts <paramref name="encryptedData"/> using the given mechanism and key. Throws
    /// <see cref="InsecureOperationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list and <see cref="AllowInsecure"/> is false.
    /// </summary>
    /// <param name="mechanism">The decryption mechanism to use.</param>
    /// <param name="keyHandle">Handle of the key to decrypt with.</param>
    /// <param name="encryptedData">Ciphertext to decrypt.</param>
    /// <returns>A freshly-allocated byte array containing the plaintext.</returns>
    public byte[] Decrypt(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> encryptedData)
    {
        using var _ = AcquireExclusive();
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(keyHandle);
        byte[] buffer = encryptedData.ToArray();
        return Decrypt(mechanism, keyHandle, buffer);
    }

    /// <summary>
    /// Decrypts single-part data
    /// </summary>
    /// <param name="mechanism">Decryption mechanism</param>
    /// <param name="keyHandle">Handle of the decryption key</param>
    /// <param name="encryptedData">Data to be decrypted</param>
    /// <returns>Decrypted data</returns>
    public byte[] Decrypt(Mechanism mechanism, ObjectHandle keyHandle, byte[] encryptedData)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);

        ArgumentNullException.ThrowIfNull(keyHandle);

        GuardMechanism((CKM)mechanism.Type);

        _logger.LogDebug("Session({SessionId})::Decrypt1", _sessionId);

        ArgumentNullException.ThrowIfNull(encryptedData);

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_DecryptInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, "C_DecryptInit");

        NativeCULong decryptedDataLen = (NativeCULong)0;
        rv = _pkcs11Library.C_Decrypt(_sessionId, encryptedData, (NativeCULong)(encryptedData.Length), null, ref decryptedDataLen);
        Pkcs11Exception.ThrowIfError(rv, "C_Decrypt");

        byte[] decryptedData = new byte[(int)decryptedDataLen];
        rv = _pkcs11Library.C_Decrypt(_sessionId, encryptedData, (NativeCULong)(encryptedData.Length), decryptedData, ref decryptedDataLen);
        Pkcs11Exception.ThrowIfError(rv, "C_Decrypt");

        if (decryptedData.Length != (int)(decryptedDataLen))
            Array.Resize(ref decryptedData, (int)(decryptedDataLen));

        return decryptedData;
    }

    /// <summary>
    /// Decrypts multi-part data
    /// </summary>
    /// <param name="mechanism">Decryption mechanism</param>
    /// <param name="keyHandle">Handle of the decryption key</param>
    /// <param name="inputStream">Input stream from which encrypted data should be read</param>
    /// <param name="outputStream">Output stream where decrypted data should be written</param>
    public void Decrypt(Mechanism mechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream)
    {
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        ArgumentNullException.ThrowIfNull(mechanism);

        ArgumentNullException.ThrowIfNull(keyHandle);

        GuardMechanism((CKM)mechanism.Type);

        _logger.LogDebug("Session({SessionId})::Decrypt2", _sessionId);

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        Decrypt(mechanism, keyHandle, inputStream, outputStream, 4096);
    }

    /// <summary>
    /// Decrypts multi-part data
    /// </summary>
    /// <param name="mechanism">Decryption mechanism</param>
    /// <param name="keyHandle">Handle of the decryption key</param>
    /// <param name="inputStream">Input stream from which encrypted data should be read</param>
    /// <param name="outputStream">Output stream where decrypted data should be written</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    public void Decrypt(Mechanism mechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream, int bufferLength)
    {
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        ArgumentNullException.ThrowIfNull(mechanism);

        ArgumentNullException.ThrowIfNull(keyHandle);

        GuardMechanism((CKM)mechanism.Type);

        _logger.LogDebug("Session({SessionId})::Decrypt3", _sessionId);

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", "bufferLength");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_DecryptInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, "C_DecryptInit");

        byte[] encryptedPart = new byte[bufferLength];
        byte[] part = new byte[bufferLength];
        NativeCULong partLen = (NativeCULong)(part.Length);

        int bytesRead = 0;
        while ((bytesRead = inputStream.Read(encryptedPart, 0, encryptedPart.Length)) > 0)
        {
            partLen = (NativeCULong)(part.Length);
            rv = _pkcs11Library.C_DecryptUpdate(_sessionId, encryptedPart, (NativeCULong)(bytesRead), part, ref partLen);
            if (rv != CKR.CKR_OK && rv != CKR.CKR_BUFFER_TOO_SMALL)
                Pkcs11Exception.ThrowIfError(rv, "C_DecryptUpdate");

            if (rv == CKR.CKR_BUFFER_TOO_SMALL)
            {
                part = new byte[(int)partLen];

                rv = _pkcs11Library.C_DecryptUpdate(_sessionId, encryptedPart, (NativeCULong)(bytesRead), part, ref partLen);
                Pkcs11Exception.ThrowIfError(rv, "C_DecryptUpdate");
            }

            outputStream.Write(part, 0, (int)(partLen));
        }

        byte[] lastPart = null;
        NativeCULong lastPartLen = (NativeCULong)0;
        rv = _pkcs11Library.C_DecryptFinal(_sessionId, null, ref lastPartLen);
        Pkcs11Exception.ThrowIfError(rv, "C_DecryptFinal");

        lastPart = new byte[(int)lastPartLen];
        rv = _pkcs11Library.C_DecryptFinal(_sessionId, lastPart, ref lastPartLen);
        Pkcs11Exception.ThrowIfError(rv, "C_DecryptFinal");

        if (lastPartLen > (NativeCULong)0)
            outputStream.Write(lastPart, 0, (int)(lastPartLen));
    }

    // === Secure-default decryption helpers =================================

    /// <summary>
    /// Decrypts ciphertext+tag produced by <see cref="EncryptAesGcm"/>.
    /// </summary>
    /// <param name="keyHandle">An AES key handle (must allow decryption).</param>
    /// <param name="iv">12-byte (96-bit) IV used during encryption.</param>
    /// <param name="ciphertextAndTag">Ciphertext concatenated with the 16-byte authentication tag.</param>
    /// <param name="aad">Additional Authenticated Data used during encryption; default is empty.</param>
    /// <returns>Decrypted plaintext.</returns>
    public byte[] DecryptAesGcm(
        ObjectHandle keyHandle,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> ciphertextAndTag,
        ReadOnlySpan<byte> aad = default)
    {
        using var _ = AcquireExclusive();
        if (iv.Length != 12)
            throw new ArgumentException("AES-GCM IV must be exactly 12 bytes (96 bits).", nameof(iv));
        if (ciphertextAndTag.Length < 16)
            throw new ArgumentException("AES-GCM ciphertext must include a 16-byte tag.", nameof(ciphertextAndTag));

        using var p = new CkmAesGcmParams(iv, aad, tagBits: 128);
        using var mechanism = new Mechanism(CKM.CKM_AES_GCM, p);
        return Decrypt(mechanism, keyHandle, ciphertextAndTag);
    }

    /// <summary>
    /// Decrypts ciphertext+tag produced by <see cref="EncryptChaCha20Poly1305"/>.
    /// </summary>
    /// <param name="keyHandle">A ChaCha20 key handle (must allow decryption).</param>
    /// <param name="nonce">12-byte (96-bit) nonce used during encryption.</param>
    /// <param name="ciphertextAndTag">Ciphertext concatenated with the 16-byte authentication tag.</param>
    /// <param name="aad">Additional Authenticated Data used during encryption; default is empty.</param>
    /// <returns>Decrypted plaintext.</returns>
    public byte[] DecryptChaCha20Poly1305(
        ObjectHandle keyHandle,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertextAndTag,
        ReadOnlySpan<byte> aad = default)
    {
        using var _ = AcquireExclusive();
        if (nonce.Length != 12)
            throw new ArgumentException("ChaCha20-Poly1305 nonce must be exactly 12 bytes (96 bits).", nameof(nonce));
        if (ciphertextAndTag.Length < 16)
            throw new ArgumentException("ChaCha20-Poly1305 ciphertext must include a 16-byte tag.", nameof(ciphertextAndTag));

        using var p = new CkmSalsa20ChaCha20Poly1305Params(nonce, aad);
        using var mechanism = new Mechanism(CKM.CKM_CHACHA20_POLY1305, p);
        return Decrypt(mechanism, keyHandle, ciphertextAndTag);
    }

    /// <summary>
    /// Decrypts ciphertext produced by <see cref="EncryptRsaOaep"/> using RSA-OAEP with
    /// SHA-256 and MGF1+SHA-256.
    /// </summary>
    /// <param name="keyHandle">An RSA private key handle (must allow decryption).</param>
    /// <param name="ciphertext">RSA-OAEP ciphertext to decrypt.</param>
    /// <returns>Decrypted plaintext.</returns>
    public byte[] DecryptRsaOaep(ObjectHandle keyHandle, ReadOnlySpan<byte> ciphertext)
    {
        using var _ = AcquireExclusive();
        using var p = new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256);
        using var mechanism = new Mechanism(CKM.CKM_RSA_PKCS_OAEP, p);
        return Decrypt(mechanism, keyHandle, ciphertext);
    }

    // === Legacy named shortcuts (gated, compile-time warning) ==============

    /// <summary>
    /// Decrypts ciphertext that was encrypted with RSA PKCS#1 v1.5 padding.
    /// <b>Use <see cref="DecryptRsaOaep"/> instead.</b>
    /// This method exists for compatibility only; it throws <see cref="InsecureOperationException"/>
    /// at runtime unless <see cref="AllowInsecure"/> is set to <c>true</c> on the session.
    /// </summary>
    [Obsolete("RSA PKCS#1 v1.5 padding is vulnerable to Bleichenbacher attacks. Use DecryptRsaOaep instead. " +
              "If you must use it, set Session.AllowInsecure = true.")]
    public byte[] DecryptRsaPkcs1V15(ObjectHandle keyHandle, ReadOnlySpan<byte> ciphertext)
    {
        using var _ = AcquireExclusive();
        using var mechanism = new Mechanism(CKM.CKM_RSA_PKCS);
        return Decrypt(mechanism, keyHandle, ciphertext);
    }
}
