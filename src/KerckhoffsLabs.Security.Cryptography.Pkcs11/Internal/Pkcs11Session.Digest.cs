using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal sealed partial class Pkcs11Session
{
    /// <summary>
    /// Digests the value of a secret key
    /// </summary>
    /// <param name="mechanism">Digesting mechanism</param>
    /// <param name="keyHandle">Handle of the secret key to be digested</param>
    /// <returns>Digest</returns>
    public byte[] DigestKey(Mechanism mechanism, ObjectHandle keyHandle)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);


        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DigestKey");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_DigestInit(_sessionId, ref ckMechanism);
        Pkcs11Exception.ThrowIfError(rv, "C_DigestInit");

        rv = _pkcs11Library.C_DigestKey(_sessionId, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, "C_DigestKey");

        NativeCULong digestLen = (NativeCULong)0;
        rv = _pkcs11Library.C_DigestFinal(_sessionId, null, ref digestLen);
        Pkcs11Exception.ThrowIfError(rv, "C_DigestFinal");

        byte[] digest = new byte[(int)digestLen];
        rv = _pkcs11Library.C_DigestFinal(_sessionId, digest, ref digestLen);
        Pkcs11Exception.ThrowIfError(rv, "C_DigestFinal");

        if (digest.Length != (int)(digestLen))
            Array.Resize(ref digest, (int)(digestLen));

        return digest;
    }

    /// <summary>
    /// Computes a digest over <paramref name="data"/> using the given mechanism. Throws
    /// <see cref="InsecureOperationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list (raw MD5 / SHA-1) and <see cref="AllowInsecure"/> is false.
    /// </summary>
    /// <param name="mechanism">The digest mechanism (typically <see cref="CKM.CKM_SHA256"/> or stronger).</param>
    /// <param name="data">Data to digest.</param>
    /// <returns>Digest bytes (length depends on the mechanism — 32 for SHA-256, 48 for SHA-384, 64 for SHA-512).</returns>
    public byte[] Digest(Mechanism mechanism, ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        ArgumentNullException.ThrowIfNull(mechanism);
        // Temporary array for the byte[]-based P/Invoke path. Replace with pinned-Span
        // P/Invoke when perf profiling proves it matters.
        byte[] buffer = data.ToArray();
        return Digest(mechanism, buffer);
    }

    /// <summary>
    /// Digests single-part data
    /// </summary>
    /// <param name="mechanism">Digesting mechanism</param>
    /// <param name="data">Data to be digested</param>
    /// <returns>Digest</returns>
    public byte[] Digest(Mechanism mechanism, byte[] data)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);

        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Digest1");

        ArgumentNullException.ThrowIfNull(data);

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_DigestInit(_sessionId, ref ckMechanism);
        Pkcs11Exception.ThrowIfError(rv, "C_DigestInit");

        NativeCULong digestLen = (NativeCULong)0;
        rv = _pkcs11Library.C_Digest(_sessionId, data, (NativeCULong)(data.Length), null, ref digestLen);
        Pkcs11Exception.ThrowIfError(rv, "C_Digest");

        byte[] digest = new byte[(int)digestLen];
        rv = _pkcs11Library.C_Digest(_sessionId, data, (NativeCULong)(data.Length), digest, ref digestLen);
        Pkcs11Exception.ThrowIfError(rv, "C_Digest");

        if (digest.Length != (int)(digestLen))
            Array.Resize(ref digest, (int)(digestLen));

        return digest;
    }

    /// <summary>
    /// Digests multi-part data
    /// </summary>
    /// <param name="mechanism">Digesting mechanism</param>
    /// <param name="inputStream">Input stream from which data should be read</param>
    /// <returns>Digest</returns>
    public byte[] Digest(Mechanism mechanism, Stream inputStream)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);

        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Digest2");

        ArgumentNullException.ThrowIfNull(inputStream);

        return Digest(mechanism, inputStream, 4096);
    }

    /// <summary>
    /// Digests multi-part data
    /// </summary>
    /// <param name="mechanism">Digesting mechanism</param>
    /// <param name="inputStream">Input stream from which data should be read</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    /// <returns>Digest</returns>
    public byte[] Digest(Mechanism mechanism, Stream inputStream, int bufferLength)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);

        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Digest3");

        ArgumentNullException.ThrowIfNull(inputStream);

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", nameof(bufferLength));

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_DigestInit(_sessionId, ref ckMechanism);
        Pkcs11Exception.ThrowIfError(rv, "C_DigestInit");

        bool finalized = false;
        try
        {
            byte[] part = new byte[bufferLength];
            int bytesRead = 0;

            while ((bytesRead = inputStream.Read(part, 0, part.Length)) > 0)
            {
                rv = _pkcs11Library.C_DigestUpdate(_sessionId, part, (NativeCULong)(bytesRead));
                Pkcs11Exception.ThrowIfError(rv, "C_DigestUpdate");
            }

            NativeCULong digestLen = (NativeCULong)0;
            rv = _pkcs11Library.C_DigestFinal(_sessionId, null, ref digestLen);
            Pkcs11Exception.ThrowIfError(rv, "C_DigestFinal");

            byte[] digest = new byte[(int)digestLen];
            rv = _pkcs11Library.C_DigestFinal(_sessionId, digest, ref digestLen);
            Pkcs11Exception.ThrowIfError(rv, "C_DigestFinal");
            finalized = true;

            if (digest.Length != (int)(digestLen))
                Array.Resize(ref digest, (int)(digestLen));

            return digest;
        }
        finally
        {
            if (!finalized)
                TryCancelOperation(CKF.CKF_DIGEST, "Digest");
        }
    }

    /// <summary>
    /// Digests and encrypts data
    /// </summary>
    /// <param name="digestingMechanism">Digesting mechanism</param>
    /// <param name="encryptionMechanism">Encryption mechanism</param>
    /// <param name="keyHandle">Handle of the encryption key</param>
    /// <param name="data">Data to be processed</param>
    /// <param name="digest">Digest</param>
    /// <param name="encryptedData">Encrypted data</param>
    public void DigestEncrypt(Mechanism digestingMechanism, Mechanism encryptionMechanism, ObjectHandle keyHandle, byte[] data, out byte[] digest, out byte[] encryptedData)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(encryptionMechanism);


        GuardMechanism((CKM)digestingMechanism.Type);
        GuardMechanism((CKM)encryptionMechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DigestEncrypt1");

        ArgumentNullException.ThrowIfNull(data);

        using (MemoryStream inputMemoryStream = new(data), outputMemorySteam = new())
        {
            digest = DigestEncrypt(digestingMechanism, encryptionMechanism, keyHandle, inputMemoryStream, outputMemorySteam);
            encryptedData = outputMemorySteam.ToArray();
        }
    }

    /// <summary>
    /// Digests and encrypts data
    /// </summary>
    /// <param name="digestingMechanism">Digesting mechanism</param>
    /// <param name="encryptionMechanism">Encryption mechanism</param>
    /// <param name="keyHandle">Handle of the encryption key</param>
    /// <param name="inputStream">Input stream from which data to be processed should be read</param>
    /// <param name="outputStream">Output stream where encrypted data should be written</param>
    /// <returns>Digest</returns>
    public byte[] DigestEncrypt(Mechanism digestingMechanism, Mechanism encryptionMechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(encryptionMechanism);


        GuardMechanism((CKM)digestingMechanism.Type);
        GuardMechanism((CKM)encryptionMechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DigestEncrypt2");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        return DigestEncrypt(digestingMechanism, encryptionMechanism, keyHandle, inputStream, outputStream, 4096);
    }

    /// <summary>
    /// Digests and encrypts data
    /// </summary>
    /// <param name="digestingMechanism">Digesting mechanism</param>
    /// <param name="encryptionMechanism">Encryption mechanism</param>
    /// <param name="keyHandle">Handle of the encryption key</param>
    /// <param name="inputStream">Input stream from which data to be processed should be read</param>
    /// <param name="outputStream">Output stream where encrypted data should be written</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    /// <returns>Digest</returns>
    public byte[] DigestEncrypt(Mechanism digestingMechanism, Mechanism encryptionMechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream, int bufferLength)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(encryptionMechanism);


        GuardMechanism((CKM)digestingMechanism.Type);
        GuardMechanism((CKM)encryptionMechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DigestEncrypt3");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", nameof(bufferLength));

        CK_MECHANISM ckDigestingMechanism = (CK_MECHANISM)digestingMechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_DigestInit(_sessionId, ref ckDigestingMechanism);
        Pkcs11Exception.ThrowIfError(rv, "C_DigestInit");

        bool encryptInited = false;
        bool encryptFinalized = false;
        bool digestFinalized = false;
        try
        {
            CK_MECHANISM ckEncryptionMechanism = (CK_MECHANISM)encryptionMechanism.ToMarshalableStructure();

            rv = _pkcs11Library.C_EncryptInit(_sessionId, ref ckEncryptionMechanism, (NativeCULong)(keyHandle.ObjectId));
            Pkcs11Exception.ThrowIfError(rv, "C_EncryptInit");
            encryptInited = true;

            byte[] part = new byte[bufferLength];
            byte[] encryptedPart = new byte[bufferLength];
            NativeCULong encryptedPartLen = (NativeCULong)(encryptedPart.Length);

            int bytesRead = 0;
            while ((bytesRead = inputStream.Read(part, 0, part.Length)) > 0)
            {
                encryptedPartLen = (NativeCULong)(encryptedPart.Length);
                rv = _pkcs11Library.C_DigestEncryptUpdate(_sessionId, part, (NativeCULong)(bytesRead), encryptedPart, ref encryptedPartLen);
                if (rv != CKR.CKR_OK && rv != CKR.CKR_BUFFER_TOO_SMALL)
                    Pkcs11Exception.ThrowIfError(rv, "C_DigestEncryptUpdate");

                if (rv == CKR.CKR_BUFFER_TOO_SMALL)
                {
                    encryptedPart = new byte[(int)encryptedPartLen];

                    rv = _pkcs11Library.C_DigestEncryptUpdate(_sessionId, part, (NativeCULong)(bytesRead), encryptedPart, ref encryptedPartLen);
                    Pkcs11Exception.ThrowIfError(rv, "C_DigestEncryptUpdate");
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
            encryptFinalized = true;

            if (lastEncryptedPartLen > (NativeCULong)0)
                outputStream.Write(lastEncryptedPart, 0, (int)(lastEncryptedPartLen));

            NativeCULong digestLen = (NativeCULong)0;
            rv = _pkcs11Library.C_DigestFinal(_sessionId, null, ref digestLen);
            Pkcs11Exception.ThrowIfError(rv, "C_DigestFinal");

            byte[] digest = new byte[(int)digestLen];
            rv = _pkcs11Library.C_DigestFinal(_sessionId, digest, ref digestLen);
            Pkcs11Exception.ThrowIfError(rv, "C_DigestFinal");
            digestFinalized = true;

            if (digest.Length != (int)(digestLen))
                Array.Resize(ref digest, (int)(digestLen));

            return digest;
        }
        finally
        {
            // Cancel whichever sub-operations are still live. Encrypt-init may not have
            // succeeded; both are independent active operations on the session per v3.0+.
            NativeCULong cancelFlags = (NativeCULong)0;
            if (!digestFinalized) cancelFlags = (NativeCULong)((ulong)cancelFlags | (ulong)CKF.CKF_DIGEST);
            if (encryptInited && !encryptFinalized) cancelFlags = (NativeCULong)((ulong)cancelFlags | (ulong)CKF.CKF_ENCRYPT);
            if ((ulong)cancelFlags != 0)
                TryCancelOperation(cancelFlags, "DigestEncrypt");
        }
    }

    /// <summary>
    /// Digests and decrypts data
    /// </summary>
    /// <param name="digestingMechanism">Digesting mechanism</param>
    /// <param name="decryptionMechanism">Decryption mechanism</param>
    /// <param name="keyHandle">Handle of the decryption key</param>
    /// <param name="data">Data to be processed</param>
    /// <param name="digest">Digest</param>
    /// <param name="decryptedData">Decrypted data</param>
    public void DecryptDigest(Mechanism digestingMechanism, Mechanism decryptionMechanism, ObjectHandle keyHandle, byte[] data, out byte[] digest, out byte[] decryptedData)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        GuardMechanism((CKM)digestingMechanism.Type);
        GuardMechanism((CKM)decryptionMechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecryptDigest1");

        ArgumentNullException.ThrowIfNull(data);

        using MemoryStream inputMemoryStream = new(data), outputMemorySteam = new();
        digest = DecryptDigest(digestingMechanism, decryptionMechanism, keyHandle, inputMemoryStream, outputMemorySteam);
        decryptedData = outputMemorySteam.ToArray();
    }

    /// <summary>
    /// Digests and decrypts data
    /// </summary>
    /// <param name="digestingMechanism">Digesting mechanism</param>
    /// <param name="decryptionMechanism">Decryption mechanism</param>
    /// <param name="keyHandle">Handle of the decryption key</param>
    /// <param name="inputStream">Input stream from which data to be processed should be read</param>
    /// <param name="outputStream">Output stream where decrypted data should be written</param>
    /// <returns>Digest</returns>
    public byte[] DecryptDigest(Mechanism digestingMechanism, Mechanism decryptionMechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        GuardMechanism((CKM)digestingMechanism.Type);
        GuardMechanism((CKM)decryptionMechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecryptDigest2");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        return DecryptDigest(digestingMechanism, decryptionMechanism, keyHandle, inputStream, outputStream, 4096);
    }

    /// <summary>
    /// Digests and decrypts data
    /// </summary>
    /// <param name="digestingMechanism">Digesting mechanism</param>
    /// <param name="decryptionMechanism">Decryption mechanism</param>
    /// <param name="keyHandle">Handle of the decryption key</param>
    /// <param name="inputStream">Input stream from which data to be processed should be read</param>
    /// <param name="outputStream">Output stream where decrypted data should be written</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    /// <returns>Digest</returns>
    public byte[] DecryptDigest(Mechanism digestingMechanism, Mechanism decryptionMechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream, int bufferLength)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        GuardMechanism((CKM)digestingMechanism.Type);
        GuardMechanism((CKM)decryptionMechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecryptDigest3");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", nameof(bufferLength));

        CK_MECHANISM ckDigestingMechanism = (CK_MECHANISM)digestingMechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_DigestInit(_sessionId, ref ckDigestingMechanism);
        Pkcs11Exception.ThrowIfError(rv, "C_DigestInit");

        bool decryptInited = false;
        bool decryptFinalized = false;
        bool digestFinalized = false;
        try
        {
            CK_MECHANISM ckDecryptionMechanism = (CK_MECHANISM)decryptionMechanism.ToMarshalableStructure();

            rv = _pkcs11Library.C_DecryptInit(_sessionId, ref ckDecryptionMechanism, (NativeCULong)(keyHandle.ObjectId));
            Pkcs11Exception.ThrowIfError(rv, "C_DecryptInit");
            decryptInited = true;

            byte[] encryptedPart = new byte[bufferLength];
            byte[] part = new byte[bufferLength];
            NativeCULong partLen = (NativeCULong)(part.Length);

            int bytesRead = 0;
            while ((bytesRead = inputStream.Read(encryptedPart, 0, encryptedPart.Length)) > 0)
            {
                partLen = (NativeCULong)(part.Length);
                rv = _pkcs11Library.C_DecryptDigestUpdate(_sessionId, encryptedPart, (NativeCULong)(bytesRead), part, ref partLen);
                if (rv != CKR.CKR_OK && rv != CKR.CKR_BUFFER_TOO_SMALL)
                    Pkcs11Exception.ThrowIfError(rv, "C_DecryptDigestUpdate");

                if (rv == CKR.CKR_BUFFER_TOO_SMALL)
                {
                    part = new byte[(int)partLen];

                    rv = _pkcs11Library.C_DecryptDigestUpdate(_sessionId, encryptedPart, (NativeCULong)(bytesRead), part, ref partLen);
                    Pkcs11Exception.ThrowIfError(rv, "C_DecryptDigestUpdate");
                }

                outputStream.Write(part, 0, (int)(partLen));
            }

            byte[]? lastPart = null;
            NativeCULong lastPartLen = (NativeCULong)0;
            rv = _pkcs11Library.C_DecryptFinal(_sessionId, null, ref lastPartLen);
            Pkcs11Exception.ThrowIfError(rv, "C_DecryptFinal");

            lastPart = new byte[(int)lastPartLen];
            rv = _pkcs11Library.C_DecryptFinal(_sessionId, lastPart, ref lastPartLen);
            Pkcs11Exception.ThrowIfError(rv, "C_DecryptFinal");
            decryptFinalized = true;

            if (lastPartLen > (NativeCULong)0)
                outputStream.Write(lastPart, 0, (int)(lastPartLen));

            NativeCULong digestLen = (NativeCULong)0;
            rv = _pkcs11Library.C_DigestFinal(_sessionId, null, ref digestLen);
            Pkcs11Exception.ThrowIfError(rv, "C_DigestFinal");

            byte[] digest = new byte[(int)digestLen];
            rv = _pkcs11Library.C_DigestFinal(_sessionId, digest, ref digestLen);
            Pkcs11Exception.ThrowIfError(rv, "C_DigestFinal");
            digestFinalized = true;

            if (digest.Length != (int)(digestLen))
                Array.Resize(ref digest, (int)(digestLen));

            return digest;
        }
        finally
        {
            NativeCULong cancelFlags = (NativeCULong)0;
            if (!digestFinalized) cancelFlags = (NativeCULong)((ulong)cancelFlags | (ulong)CKF.CKF_DIGEST);
            if (decryptInited && !decryptFinalized) cancelFlags = (NativeCULong)((ulong)cancelFlags | (ulong)CKF.CKF_DECRYPT);
            if ((ulong)cancelFlags != 0)
                TryCancelOperation(cancelFlags, "DecryptDigest");
        }
    }

    // === Legacy named shortcuts (gated, compile-time warning) ==============
    // NOTE: SHA-256/384/512 are exposed through the BCL adapters SHA256Pkcs11 / SHA384Pkcs11 /
    // SHA512Pkcs11 (digesting via Workspace.Digest); only the gated MD5/SHA-1 shortcuts remain here.

    /// <summary>
    /// Computes an MD5 digest. **Use SHA-256 (<c>SHA256Pkcs11</c>) or stronger instead.** Throws
    /// <see cref="InsecureOperationException"/> at runtime unless
    /// <see cref="AllowInsecure"/> is set on the session.
    /// </summary>
    [Obsolete("MD5 is a broken hash function with practical collisions. " +
              "Use SHA-256 (SHA256Pkcs11) or stronger instead. " +
              "If you must use it, set Pkcs11Workspace.AllowInsecure = true.")]
    public byte[] DigestMd5(ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        using var mechanism = new Mechanism(CKM.CKM_MD5);
        return Digest(mechanism, data);
    }

    /// <summary>
    /// Computes a SHA-1 digest. **Use SHA-256 (<c>SHA256Pkcs11</c>) or stronger instead.** Throws
    /// <see cref="InsecureOperationException"/> at runtime unless
    /// <see cref="AllowInsecure"/> is set on the session.
    /// </summary>
    [Obsolete("SHA-1 is broken (SHAttered demonstrated practical collisions). " +
              "Use SHA-256 (SHA256Pkcs11) or stronger instead. " +
              "If you must use it, set Pkcs11Workspace.AllowInsecure = true.")]
    public byte[] DigestSha1(ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        using var mechanism = new Mechanism(CKM.CKM_SHA_1);
        return Digest(mechanism, data);
    }
}
