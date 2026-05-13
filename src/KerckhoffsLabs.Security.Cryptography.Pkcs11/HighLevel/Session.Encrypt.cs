using KerckhoffsLabs.Security.Cryptography.Pkcs11;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public partial class Session
{
    /// <summary>
    /// Encrypts <paramref name="data"/> using the given mechanism and key. Throws
    /// <see cref="InsecureOperationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list and <see cref="AllowInsecure"/> is false.
    /// </summary>
    /// <param name="mechanism">The encryption mechanism to use.</param>
    /// <param name="keyHandle">Handle of the key to encrypt with.</param>
    /// <param name="data">Plaintext to encrypt.</param>
    /// <returns>A freshly-allocated byte array containing the ciphertext.</returns>
    public byte[] Encrypt(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(keyHandle);
        // Temporary array for the byte[]-based P/Invoke path. Replace with pinned-Span
        // P/Invoke when perf profiling proves it matters.
        byte[] buffer = data.ToArray();
        return Encrypt(mechanism, keyHandle, buffer);
    }

    /// <summary>
    /// Encrypts single-part data
    /// </summary>
    /// <param name="mechanism">Encryption mechanism</param>
    /// <param name="keyHandle">Handle of the encryption key</param>
    /// <param name="data">Data to be encrypted</param>
    /// <returns>Encrypted data</returns>
    public byte[] Encrypt(Mechanism mechanism, ObjectHandle keyHandle, byte[] data)
    {
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.LogDebug("Session({SessionId})::Encrypt1", _sessionId);

        if (data == null)
            throw new ArgumentNullException("data");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_EncryptInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, "C_EncryptInit");

        NativeCULong encryptedDataLen = (NativeCULong)0;
        rv = _pkcs11Library.C_Encrypt(_sessionId, data, (NativeCULong)(data.Length), null, ref encryptedDataLen);
        Pkcs11Exception.ThrowIfError(rv, "C_Encrypt");

        byte[] encryptedData = new byte[(int)encryptedDataLen];
        rv = _pkcs11Library.C_Encrypt(_sessionId, data, (NativeCULong)(data.Length), encryptedData, ref encryptedDataLen);
        Pkcs11Exception.ThrowIfError(rv, "C_Encrypt");

        if (encryptedData.Length != (int)(encryptedDataLen))
            Array.Resize(ref encryptedData, (int)(encryptedDataLen));

        return encryptedData;
    }

    /// <summary>
    /// Encrypts multi-part data
    /// </summary>
    /// <param name="mechanism">Encryption mechanism</param>
    /// <param name="keyHandle">Handle of the encryption key</param>
    /// <param name="inputStream">Input stream from which data to be encrypted should be read</param>
    /// <param name="outputStream">Output stream where encrypted data should be written</param>
    public void Encrypt(Mechanism mechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream)
    {
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.LogDebug("Session({SessionId})::Encrypt2", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (outputStream == null)
            throw new ArgumentNullException("outputStream");

        Encrypt(mechanism, keyHandle, inputStream, outputStream, 4096);
    }

    /// <summary>
    /// Encrypts multi-part data
    /// </summary>
    /// <param name="mechanism">Encryption mechanism</param>
    /// <param name="keyHandle">Handle of the encryption key</param>
    /// <param name="inputStream">Input stream from which data to be encrypted should be read</param>
    /// <param name="outputStream">Output stream where encrypted data should be written</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    public void Encrypt(Mechanism mechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream, int bufferLength)
    {
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.LogDebug("Session({SessionId})::Encrypt3", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (outputStream == null)
            throw new ArgumentNullException("outputStream");

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", "bufferLength");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_EncryptInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, "C_EncryptInit");

        byte[] part = new byte[bufferLength];
        byte[] encryptedPart = new byte[bufferLength];
        NativeCULong encryptedPartLen = (NativeCULong)(encryptedPart.Length);

        int bytesRead = 0;
        while ((bytesRead = inputStream.Read(part, 0, part.Length)) > 0)
        {
            encryptedPartLen = (NativeCULong)(encryptedPart.Length);
            rv = _pkcs11Library.C_EncryptUpdate(_sessionId, part, (NativeCULong)(bytesRead), encryptedPart, ref encryptedPartLen);
            if (rv != CKR.CKR_OK && rv != CKR.CKR_BUFFER_TOO_SMALL)
                Pkcs11Exception.ThrowIfError(rv, "C_EncryptUpdate");

            if (rv == CKR.CKR_BUFFER_TOO_SMALL)
            {
                encryptedPart = new byte[(int)encryptedPartLen];

                rv = _pkcs11Library.C_EncryptUpdate(_sessionId, part, (NativeCULong)(bytesRead), encryptedPart, ref encryptedPartLen);
                Pkcs11Exception.ThrowIfError(rv, "C_EncryptUpdate");
            }

            outputStream.Write(encryptedPart, 0, (int)(encryptedPartLen));
        }

        byte[] lastEncryptedPart = null;
        NativeCULong lastEncryptedPartLen = (NativeCULong)0;
        rv = _pkcs11Library.C_EncryptFinal(_sessionId, null, ref lastEncryptedPartLen);
        Pkcs11Exception.ThrowIfError(rv, "C_EncryptFinal");

        lastEncryptedPart = new byte[(int)lastEncryptedPartLen];
        rv = _pkcs11Library.C_EncryptFinal(_sessionId, lastEncryptedPart, ref lastEncryptedPartLen);
        Pkcs11Exception.ThrowIfError(rv, "C_EncryptFinal");

        if (lastEncryptedPartLen > (NativeCULong)0)
            outputStream.Write(lastEncryptedPart, 0, (int)(lastEncryptedPartLen));
    }

    // === Secure-default encryption helpers =================================

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> using AES-GCM with a 96-bit IV and a 128-bit
    /// authentication tag. Produces ciphertext concatenated with the tag (PKCS#11 standard
    /// output format for AEAD).
    /// </summary>
    /// <param name="keyHandle">An AES key handle (must allow encryption).</param>
    /// <param name="iv">12-byte (96-bit) nonce, MUST be unique per key.</param>
    /// <param name="plaintext">Data to encrypt.</param>
    /// <param name="aad">Additional Authenticated Data; default is empty.</param>
    /// <returns>Ciphertext + 16-byte tag.</returns>
    public byte[] EncryptAesGcm(
        ObjectHandle keyHandle,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> aad = default)
    {
        using var _ = AcquireExclusive();
        if (iv.Length != 12)
            throw new ArgumentException("AES-GCM IV must be exactly 12 bytes (96 bits).", nameof(iv));

        using var p = new CkmAesGcmParams(iv, aad, tagBits: 128);
        using var mechanism = new Mechanism(CKM.CKM_AES_GCM, p);
        return Encrypt(mechanism, keyHandle, plaintext);
    }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> using ChaCha20-Poly1305 with a 96-bit nonce.
    /// Produces ciphertext concatenated with a 128-bit tag.
    /// </summary>
    /// <param name="keyHandle">A ChaCha20 key handle (must allow encryption).</param>
    /// <param name="nonce">12-byte (96-bit) nonce, MUST be unique per key.</param>
    /// <param name="plaintext">Data to encrypt.</param>
    /// <param name="aad">Additional Authenticated Data; default is empty.</param>
    /// <returns>Ciphertext + 16-byte tag.</returns>
    public byte[] EncryptChaCha20Poly1305(
        ObjectHandle keyHandle,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> aad = default)
    {
        using var _ = AcquireExclusive();
        if (nonce.Length != 12)
            throw new ArgumentException("ChaCha20-Poly1305 nonce must be exactly 12 bytes (96 bits).", nameof(nonce));

        using var p = new CkmSalsa20ChaCha20Poly1305Params(nonce, aad);
        using var mechanism = new Mechanism(CKM.CKM_CHACHA20_POLY1305, p);
        return Encrypt(mechanism, keyHandle, plaintext);
    }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> using RSA-OAEP with SHA-256 and MGF1+SHA-256.
    /// Suitable for wrapping symmetric keys; not for bulk data (plaintext must be smaller
    /// than the RSA modulus minus 2*hashSize+2).
    /// </summary>
    /// <param name="keyHandle">An RSA public key handle (must allow encryption).</param>
    /// <param name="plaintext">Data to encrypt.</param>
    /// <returns>RSA-OAEP encrypted ciphertext.</returns>
    public byte[] EncryptRsaOaep(ObjectHandle keyHandle, ReadOnlySpan<byte> plaintext)
    {
        using var _ = AcquireExclusive();
        using var p = new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256);
        using var mechanism = new Mechanism(CKM.CKM_RSA_PKCS_OAEP, p);
        return Encrypt(mechanism, keyHandle, plaintext);
    }

    // === Legacy named shortcuts (gated, compile-time warning) ==============

    /// <summary>
    /// Encrypts using RSA PKCS#1 v1.5 padding. <b>Use <see cref="EncryptRsaOaep"/> instead.</b>
    /// This method exists for compatibility only; it throws <see cref="InsecureOperationException"/>
    /// at runtime unless <see cref="AllowInsecure"/> is set to <c>true</c> on the session.
    /// </summary>
    [Obsolete("RSA PKCS#1 v1.5 padding is vulnerable to Bleichenbacher attacks. Use EncryptRsaOaep instead. " +
              "If you must use it, set Session.AllowInsecure = true.")]
    public byte[] EncryptRsaPkcs1V15(ObjectHandle keyHandle, ReadOnlySpan<byte> plaintext)
    {
        using var _ = AcquireExclusive();
        using var mechanism = new Mechanism(CKM.CKM_RSA_PKCS);
        return Encrypt(mechanism, keyHandle, plaintext);
    }
}
