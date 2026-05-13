using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public partial class Session
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
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.LogDebug("Session({SessionId})::DigestKey", _sessionId);

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
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        GuardMechanism((CKM)mechanism.Type);

        _logger.LogDebug("Session({SessionId})::Digest1", _sessionId);

        if (data == null)
            throw new ArgumentNullException("data");

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
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        GuardMechanism((CKM)mechanism.Type);

        _logger.LogDebug("Session({SessionId})::Digest2", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

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
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        GuardMechanism((CKM)mechanism.Type);

        _logger.LogDebug("Session({SessionId})::Digest3", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", "bufferLength");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_DigestInit(_sessionId, ref ckMechanism);
        Pkcs11Exception.ThrowIfError(rv, "C_DigestInit");

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

        if (digest.Length != (int)(digestLen))
            Array.Resize(ref digest, (int)(digestLen));

        return digest;
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
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (digestingMechanism == null)
            throw new ArgumentNullException("digestingMechanism");

        if (encryptionMechanism == null)
            throw new ArgumentNullException("encryptionMechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)digestingMechanism.Type);
        GuardMechanism((CKM)encryptionMechanism.Type);

        _logger.LogDebug("Session({SessionId})::DigestEncrypt1", _sessionId);

        if (data == null)
            throw new ArgumentNullException("data");

        using (MemoryStream inputMemoryStream = new MemoryStream(data), outputMemorySteam = new MemoryStream())
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
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (digestingMechanism == null)
            throw new ArgumentNullException("digestingMechanism");

        if (encryptionMechanism == null)
            throw new ArgumentNullException("encryptionMechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)digestingMechanism.Type);
        GuardMechanism((CKM)encryptionMechanism.Type);

        _logger.LogDebug("Session({SessionId})::DigestEncrypt2", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (outputStream == null)
            throw new ArgumentNullException("outputStream");

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
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (digestingMechanism == null)
            throw new ArgumentNullException("digestingMechanism");

        if (encryptionMechanism == null)
            throw new ArgumentNullException("encryptionMechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)digestingMechanism.Type);
        GuardMechanism((CKM)encryptionMechanism.Type);

        _logger.LogDebug("Session({SessionId})::DigestEncrypt3", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (outputStream == null)
            throw new ArgumentNullException("outputStream");

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", "bufferLength");

        CK_MECHANISM ckDigestingMechanism = (CK_MECHANISM)digestingMechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_DigestInit(_sessionId, ref ckDigestingMechanism);
        Pkcs11Exception.ThrowIfError(rv, "C_DigestInit");

        CK_MECHANISM ckEncryptionMechanism = (CK_MECHANISM)encryptionMechanism.ToMarshalableStructure();

        rv = _pkcs11Library.C_EncryptInit(_sessionId, ref ckEncryptionMechanism, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, "C_EncryptInit");

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

        byte[] lastEncryptedPart = null;
        NativeCULong lastEncryptedPartLen = (NativeCULong)0;
        rv = _pkcs11Library.C_EncryptFinal(_sessionId, null, ref lastEncryptedPartLen);
        Pkcs11Exception.ThrowIfError(rv, "C_EncryptFinal");

        lastEncryptedPart = new byte[(int)lastEncryptedPartLen];
        rv = _pkcs11Library.C_EncryptFinal(_sessionId, lastEncryptedPart, ref lastEncryptedPartLen);
        Pkcs11Exception.ThrowIfError(rv, "C_EncryptFinal");

        if (lastEncryptedPartLen > (NativeCULong)0)
            outputStream.Write(lastEncryptedPart, 0, (int)(lastEncryptedPartLen));

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
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (digestingMechanism == null)
            throw new ArgumentNullException("digestingMechanism");

        if (decryptionMechanism == null)
            throw new ArgumentNullException("decryptionMechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)digestingMechanism.Type);
        GuardMechanism((CKM)decryptionMechanism.Type);

        _logger.LogDebug("Session({SessionId})::DecryptDigest1", _sessionId);

        if (data == null)
            throw new ArgumentNullException("data");

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
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (digestingMechanism == null)
            throw new ArgumentNullException("digestingMechanism");

        if (decryptionMechanism == null)
            throw new ArgumentNullException("decryptionMechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)digestingMechanism.Type);
        GuardMechanism((CKM)decryptionMechanism.Type);

        _logger.LogDebug("Session({SessionId})::DecryptDigest2", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (outputStream == null)
            throw new ArgumentNullException("outputStream");

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
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (digestingMechanism == null)
            throw new ArgumentNullException("digestingMechanism");

        if (decryptionMechanism == null)
            throw new ArgumentNullException("decryptionMechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)digestingMechanism.Type);
        GuardMechanism((CKM)decryptionMechanism.Type);

        _logger.LogDebug("Session({SessionId})::DecryptDigest3", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (outputStream == null)
            throw new ArgumentNullException("outputStream");

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", "bufferLength");

        CK_MECHANISM ckDigestingMechanism = (CK_MECHANISM)digestingMechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_DigestInit(_sessionId, ref ckDigestingMechanism);
        Pkcs11Exception.ThrowIfError(rv, "C_DigestInit");

        CK_MECHANISM ckDecryptionMechanism = (CK_MECHANISM)decryptionMechanism.ToMarshalableStructure();

        rv = _pkcs11Library.C_DecryptInit(_sessionId, ref ckDecryptionMechanism, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, "C_DecryptInit");

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

        byte[] lastPart = null;
        NativeCULong lastPartLen = (NativeCULong)0;
        rv = _pkcs11Library.C_DecryptFinal(_sessionId, null, ref lastPartLen);
        Pkcs11Exception.ThrowIfError(rv, "C_DecryptFinal");

        lastPart = new byte[(int)lastPartLen];
        rv = _pkcs11Library.C_DecryptFinal(_sessionId, lastPart, ref lastPartLen);
        Pkcs11Exception.ThrowIfError(rv, "C_DecryptFinal");

        if (lastPartLen > (NativeCULong)0)
            outputStream.Write(lastPart, 0, (int)(lastPartLen));

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

    // === Secure-default digest helpers =====================================

    /// <summary>Computes a SHA-256 digest over <paramref name="data"/>. Output is 32 bytes.</summary>
    /// <param name="data">Data to digest.</param>
    /// <returns>32-byte SHA-256 digest.</returns>
    public byte[] DigestSha256(ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        using var mechanism = new Mechanism(CKM.CKM_SHA256);
        return Digest(mechanism, data);
    }

    /// <summary>Computes a SHA-384 digest over <paramref name="data"/>. Output is 48 bytes.</summary>
    /// <param name="data">Data to digest.</param>
    /// <returns>48-byte SHA-384 digest.</returns>
    public byte[] DigestSha384(ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        using var mechanism = new Mechanism(CKM.CKM_SHA384);
        return Digest(mechanism, data);
    }

    /// <summary>Computes a SHA-512 digest over <paramref name="data"/>. Output is 64 bytes.</summary>
    /// <param name="data">Data to digest.</param>
    /// <returns>64-byte SHA-512 digest.</returns>
    public byte[] DigestSha512(ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        using var mechanism = new Mechanism(CKM.CKM_SHA512);
        return Digest(mechanism, data);
    }

    // === Legacy named shortcuts (gated, compile-time warning) ==============

    /// <summary>
    /// Computes an MD5 digest. **Use <see cref="DigestSha256"/> instead.** Throws
    /// <see cref="InsecureOperationException"/> at runtime unless
    /// <see cref="AllowInsecure"/> is set on the session.
    /// </summary>
    [Obsolete("MD5 is a broken hash function with practical collisions. " +
              "Use DigestSha256 (or stronger) instead. " +
              "If you must use it, set Session.AllowInsecure = true.")]
    public byte[] DigestMd5(ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        using var mechanism = new Mechanism(CKM.CKM_MD5);
        return Digest(mechanism, data);
    }

    /// <summary>
    /// Computes a SHA-1 digest. **Use <see cref="DigestSha256"/> instead.** Throws
    /// <see cref="InsecureOperationException"/> at runtime unless
    /// <see cref="AllowInsecure"/> is set on the session.
    /// </summary>
    [Obsolete("SHA-1 is broken (SHAttered demonstrated practical collisions). " +
              "Use DigestSha256 (or stronger) instead. " +
              "If you must use it, set Session.AllowInsecure = true.")]
    public byte[] DigestSha1(ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        using var mechanism = new Mechanism(CKM.CKM_SHA_1);
        return Digest(mechanism, data);
    }
}
