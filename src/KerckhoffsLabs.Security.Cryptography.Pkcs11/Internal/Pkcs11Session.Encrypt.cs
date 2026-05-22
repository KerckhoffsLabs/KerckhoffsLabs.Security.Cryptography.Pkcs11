using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal sealed partial class Pkcs11Session
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
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);


        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Encrypt1");

        ArgumentNullException.ThrowIfNull(data);

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_EncryptInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, "C_EncryptInit");

        // Use input length as the initial output buffer size — avoids a null-probe call
        // that can cause AEAD tokens to run full tag verification on the probe.
        // Resize via CKR_BUFFER_TOO_SMALL if the token needs more space (e.g. AEAD tag appended).
        NativeCULong encryptedDataLen = (NativeCULong)data.Length;
        byte[] encryptedData = new byte[data.Length];
        rv = _pkcs11Library.C_Encrypt(_sessionId, data, (NativeCULong)data.Length, encryptedData, ref encryptedDataLen);

        if (rv == CKR.CKR_BUFFER_TOO_SMALL)
        {
            encryptedData = new byte[(int)encryptedDataLen];
            rv = _pkcs11Library.C_Encrypt(_sessionId, data, (NativeCULong)data.Length, encryptedData, ref encryptedDataLen);
        }

        Pkcs11Exception.ThrowIfError(rv, "C_Encrypt");

        if (encryptedData.Length != (int)encryptedDataLen)
            Array.Resize(ref encryptedData, (int)encryptedDataLen);

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
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);


        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Encrypt2");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

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
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);


        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Encrypt3");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", nameof(bufferLength));

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_EncryptInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, "C_EncryptInit");

        bool finalized = false;
        try
        {
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

            byte[]? lastEncryptedPart = null;
            NativeCULong lastEncryptedPartLen = (NativeCULong)0;
            rv = _pkcs11Library.C_EncryptFinal(_sessionId, null, ref lastEncryptedPartLen);
            Pkcs11Exception.ThrowIfError(rv, "C_EncryptFinal");

            lastEncryptedPart = new byte[(int)lastEncryptedPartLen];
            rv = _pkcs11Library.C_EncryptFinal(_sessionId, lastEncryptedPart, ref lastEncryptedPartLen);
            Pkcs11Exception.ThrowIfError(rv, "C_EncryptFinal");
            finalized = true;

            if (lastEncryptedPartLen > (NativeCULong)0)
                outputStream.Write(lastEncryptedPart, 0, (int)(lastEncryptedPartLen));
        }
        finally
        {
            if (!finalized)
                TryCancelOperation(CKF.CKF_ENCRYPT, "Encrypt");
        }
    }

    // === Secure-default encryption helpers =================================
    // NOTE: the AES-GCM convenience moved to the AesGcmPkcs11 BCL adapter (over Pkcs11Key), which
    // uses the message API when available; this raw-ObjectHandle session layer keeps only the
    // mechanisms the adapter does not yet wrap.

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
              "If you must use it, set Pkcs11Workspace.AllowInsecure = true.")]
    public byte[] EncryptRsaPkcs1V15(ObjectHandle keyHandle, ReadOnlySpan<byte> plaintext)
    {
        using var _ = AcquireExclusive();
        using var mechanism = new Mechanism(CKM.CKM_RSA_PKCS);
        return Encrypt(mechanism, keyHandle, plaintext);
    }

    /// <summary>
    /// True when the loaded PKCS#11 library exposes the v3.0 message-based AEAD API
    /// (<see cref="MessageEncrypt"/> / <see cref="MessageDecrypt"/> use it). False on
    /// v2.40 libraries — callers must use <see cref="Encrypt(Mechanism, ObjectHandle, ReadOnlySpan{byte})"/> / <see cref="Decrypt(Mechanism, ObjectHandle, ReadOnlySpan{byte})"/>
    /// with the legacy CK_GCM_PARAMS / CK_CCM_PARAMS / CK_SALSA20_CHACHA20_POLY1305_PARAMS
    /// instead.
    /// </summary>
    public bool SupportsMessageApi => _pkcs11Library.IsMessageApiSupported;

    /// <summary>
    /// One-shot AEAD encrypt via the PKCS#11 v3.0 message-based API
    /// (C_MessageEncryptInit + C_EncryptMessage + C_MessageEncryptFinal). The per-message
    /// nonce / IV / tag flow lives entirely in <paramref name="messageParams"/>; the
    /// authentication tag is read back through the wrapper's <c>CopyTagTo</c> /
    /// <c>CopyMacTo</c> method after this call.
    /// </summary>
    /// <param name="mechanism">AEAD mechanism (CKM_AES_GCM / CKM_AES_CCM / CKM_CHACHA20_POLY1305 / CKM_SALSA20_POLY1305).</param>
    /// <param name="keyHandle">Symmetric key handle.</param>
    /// <param name="messageParams">Per-message parameters (e.g. <see cref="CkmGcmMessageParams"/>).</param>
    /// <param name="associatedData">Optional Additional Authenticated Data.</param>
    /// <param name="plaintext">Bytes to encrypt.</param>
    /// <returns>Ciphertext (without the tag — tag is in <paramref name="messageParams"/>).</returns>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> when the loaded library is v2.40.</exception>
    public byte[] MessageEncrypt(
        Mechanism mechanism,
        ObjectHandle keyHandle,
        MechanismParameters messageParams,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> plaintext)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(messageParams);

        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "MessageEncrypt");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();
        CKR rv = _pkcs11Library.C_MessageEncryptInit(_sessionId, ref ckMechanism, (NativeCULong)keyHandle.ObjectId);
        Pkcs11Exception.ThrowIfError(rv, "C_MessageEncryptInit");

        try
        {
            object paramsStruct = messageParams.ToMarshalableStructure();
            int paramsSize = UnmanagedMemory.SizeOf(paramsStruct.GetType());
            IntPtr paramsPtr = UnmanagedMemory.Allocate(paramsSize);
            try
            {
                UnmanagedMemory.Write(paramsPtr, paramsStruct);

                byte[] aad = associatedData.IsEmpty ? [] : associatedData.ToArray();
                byte[] pt = plaintext.ToArray();

                NativeCULong ctLen = (NativeCULong)0;
                rv = _pkcs11Library.C_EncryptMessage(
                    _sessionId, paramsPtr, (NativeCULong)paramsSize,
                    aad, (NativeCULong)aad.Length,
                    pt, (NativeCULong)pt.Length,
                    null!, ref ctLen);
                Pkcs11Exception.ThrowIfError(rv, "C_EncryptMessage (length probe)");

                byte[] ct = new byte[(int)ctLen];
                rv = _pkcs11Library.C_EncryptMessage(
                    _sessionId, paramsPtr, (NativeCULong)paramsSize,
                    aad, (NativeCULong)aad.Length,
                    pt, (NativeCULong)pt.Length,
                    ct, ref ctLen);
                Pkcs11Exception.ThrowIfError(rv, "C_EncryptMessage");

                if (ct.Length != (int)ctLen)
                    Array.Resize(ref ct, (int)ctLen);

                return ct;
            }
            finally
            {
                UnmanagedMemory.Free(ref paramsPtr);
            }
        }
        finally
        {
            CKR finalRv = _pkcs11Library.C_MessageEncryptFinal(_sessionId);
            if (finalRv != CKR.CKR_OK)
                _logger.LogWarning("C_MessageEncryptFinal returned {Rv}", finalRv);
        }
    }
}
