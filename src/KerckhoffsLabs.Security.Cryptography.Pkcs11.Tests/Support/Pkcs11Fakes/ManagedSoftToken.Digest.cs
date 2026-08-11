using System.Security.Cryptography;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

// Digest family: keyless one-shot C_DigestInit + C_Digest (MD5/SHA-1/SHA-2/SHA-3), via the BCL.
internal sealed partial class ManagedSoftToken
{
    private readonly Dictionary<ulong, ulong> _digestOps = [];

    public override CKR C_DigestInit(NativeCULong session, ref CK_MECHANISM mechanism)
    {
        if (!_sessions.Contains((ulong)session)) return CKR.CKR_SESSION_HANDLE_INVALID;
        if (!IsDigest((CKM)(ulong)mechanism.Mechanism)) return CKR.CKR_MECHANISM_INVALID;
        _digestOps[(ulong)session] = (ulong)mechanism.Mechanism;
        return CKR.CKR_OK;
    }

    public override CKR C_Digest(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> digest, out NativeCULong digestLen)
    {
        digestLen = (NativeCULong)0;
        digestLen = (NativeCULong)0;
        if (!_digestOps.TryGetValue((ulong)session, out var mech)) return CKR.CKR_OPERATION_NOT_INITIALIZED;

        byte[] result;
        try { result = ComputeDigest((CKM)mech, data.ToArray()); }
        catch (PlatformNotSupportedException) { _digestOps.Remove((ulong)session); return CKR.CKR_MECHANISM_INVALID; }

        if (digest.IsEmpty) { digestLen = (NativeCULong)(ulong)result.Length; return CKR.CKR_OK; }
        if (digest.Length < result.Length) { digestLen = (NativeCULong)(ulong)result.Length; return CKR.CKR_BUFFER_TOO_SMALL; }

        result.AsSpan(0, result.Length).CopyTo(digest);
        digestLen = (NativeCULong)(ulong)result.Length;
        _digestOps.Remove((ulong)session);
        return CKR.CKR_OK;
    }

    private static bool IsDigest(CKM m) => m is
        CKM.CKM_MD5 or CKM.CKM_SHA_1 or CKM.CKM_SHA256 or CKM.CKM_SHA384 or CKM.CKM_SHA512
        or CKM.CKM_SHA3_256 or CKM.CKM_SHA3_384 or CKM.CKM_SHA3_512;

    private static byte[] ComputeDigest(CKM mech, byte[] data) => mech switch
    {
        CKM.CKM_MD5 => MD5.HashData(data),
        CKM.CKM_SHA_1 => SHA1.HashData(data),
        CKM.CKM_SHA256 => SHA256.HashData(data),
        CKM.CKM_SHA384 => SHA384.HashData(data),
        CKM.CKM_SHA512 => SHA512.HashData(data),
        CKM.CKM_SHA3_256 => SHA3_256.HashData(data),
        CKM.CKM_SHA3_384 => SHA3_384.HashData(data),
        CKM.CKM_SHA3_512 => SHA3_512.HashData(data),
        _ => throw new CryptographicException($"ManagedSoftToken: unsupported digest {mech}."),
    };
}
