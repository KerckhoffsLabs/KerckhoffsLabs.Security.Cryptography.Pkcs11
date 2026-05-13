using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public sealed partial class Pkcs11Key
{
    /// <summary>
    /// Signs <paramref name="data"/> using the given mechanism. Requires the key to
    /// carry a private handle (symmetric keys are sign-capable too).
    /// </summary>
    /// <param name="mechanism">The signing mechanism.</param>
    /// <param name="data">The data to sign.</param>
    /// <returns>The signature bytes.</returns>
    /// <exception cref="Pkcs11Exception">Thrown if the key has no private handle.</exception>
    public byte[] Sign(Mechanism mechanism, ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);

        if (_privateHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Sign (no private handle)");

        return _workspace.Session.Sign(mechanism, _privateHandle, data);
    }

    /// <summary>
    /// Verifies <paramref name="signature"/> over <paramref name="data"/> using the
    /// given mechanism. Uses the real public handle when present; falls back to managed
    /// verification via the synthesized RSA/EC public parameters when no real handle
    /// exists.
    /// </summary>
    /// <returns><c>true</c> if the signature is valid, <c>false</c> if not.</returns>
    /// <exception cref="Pkcs11Exception">Thrown if no public material is reachable.</exception>
    public bool Verify(Mechanism mechanism, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);

        // Prefer the real public handle.
        if (!_publicHandle.IsInvalid)
        {
            _workspace.Session.Verify(mechanism, _publicHandle, data, signature, out bool isValid);
            return isValid;
        }

        // Fall back to managed verify via synthesized public parameters.
        if (_keyType == CKK.CKK_RSA)
        {
            var rsaParams = GetSynthesizedRsaParameters();
            if (rsaParams is not null)
                return VerifyRsaInManaged(mechanism, rsaParams.Value, data, signature);
        }
        else if (_keyType == CKK.CKK_EC)
        {
            var ecParams = GetSynthesizedEcParameters();
            if (ecParams is not null)
                return VerifyEcInManaged(mechanism, ecParams.Value, data, signature);
        }

        throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
            "Pkcs11Key.Verify (no public handle and synthesis unavailable)");
    }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> using this key. Symmetric keys use the
    /// single handle; asymmetric public-side encryption (RSA-OAEP / RSA-PKCS) uses the
    /// public handle.
    /// </summary>
    public byte[] Encrypt(Mechanism mechanism, ReadOnlySpan<byte> plaintext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);

        ObjectHandle handle = IsAsymmetricKeyType(_keyType)
            ? _publicHandle
            : _privateHandle;

        if (handle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Encrypt (handle unavailable)");

        return _workspace.Session.Encrypt(mechanism, handle, plaintext);
    }

    /// <summary>
    /// Decrypts <paramref name="ciphertext"/> using this key. Symmetric uses the single
    /// handle; asymmetric uses the private handle.
    /// </summary>
    public byte[] Decrypt(Mechanism mechanism, ReadOnlySpan<byte> ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);

        if (_privateHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Decrypt (no private handle)");

        return _workspace.Session.Decrypt(mechanism, _privateHandle, ciphertext);
    }

    /// <summary>
    /// Wraps <paramref name="targetKey"/> with this key. This key is the wrapper; the
    /// target's private (or symmetric) handle is consumed by the wrap operation.
    /// </summary>
    /// <param name="mechanism">The wrap mechanism (e.g. <see cref="CKM.CKM_AES_KEY_WRAP"/>).</param>
    /// <param name="targetKey">The key being wrapped. Must carry a private/symmetric handle.</param>
    /// <returns>The wrapped key bytes — opaque blob to be transported / stored.</returns>
    public byte[] Wrap(Mechanism mechanism, Pkcs11Key targetKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(targetKey);

        ObjectHandle wrapHandle = IsAsymmetricKeyType(_keyType) ? _publicHandle : _privateHandle;
        if (wrapHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Wrap (wrapping-key handle unavailable)");

        ObjectHandle targetHandle = targetKey._privateHandle.IsInvalid
            ? targetKey._publicHandle
            : targetKey._privateHandle;
        if (targetHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Wrap (target-key handle unavailable)");

        return _workspace.Session.WrapKey(mechanism, wrapHandle, targetHandle);
    }

    /// <summary>
    /// Unwraps the byte blob <paramref name="wrappedBytes"/> using this key as the
    /// unwrapping key, into a new on-token object described by
    /// <paramref name="template"/>.
    /// </summary>
    /// <returns>A new <see cref="Pkcs11Key"/> wrapping the unwrapped object.</returns>
    public Pkcs11Key Unwrap(Mechanism mechanism, ReadOnlySpan<byte> wrappedBytes, ObjectTemplate template)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(template);

        ObjectHandle unwrapHandle = _privateHandle.IsInvalid ? _publicHandle : _privateHandle;
        if (unwrapHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Unwrap (unwrapping-key handle unavailable)");

        ObjectHandle resulting = _workspace.Session.UnwrapKey(
            mechanism, unwrapHandle, wrappedBytes, template.Attributes.ToList());

        return _workspace.HydrateExistingHandleAsKey(resulting);
    }

    /// <summary>
    /// Derives a new key from this key.
    /// </summary>
    public Pkcs11Key Derive(Mechanism mechanism, ObjectTemplate template)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(template);

        ObjectHandle baseHandle = _privateHandle.IsInvalid ? _publicHandle : _privateHandle;
        if (baseHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Derive (base-key handle unavailable)");

        ObjectHandle resulting = _workspace.Session.DeriveKey(
            mechanism, baseHandle, template.Attributes.ToList());
        return _workspace.HydrateExistingHandleAsKey(resulting);
    }

    private static bool IsAsymmetricKeyType(CKK keyType) => keyType switch
    {
        CKK.CKK_RSA or CKK.CKK_DSA or CKK.CKK_EC or CKK.CKK_EC_EDWARDS => true,
        _ => false,
    };

    private static bool VerifyRsaInManaged(
        Mechanism mechanism,
        System.Security.Cryptography.RSAParameters rsaParams,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
    {
        using var rsa = System.Security.Cryptography.RSA.Create();
        rsa.ImportParameters(rsaParams);

        var (hashName, padding) = MapRsaSignMechanism(mechanism);
        return rsa.VerifyData(data, signature, hashName, padding);
    }

    private static bool VerifyEcInManaged(
        Mechanism mechanism,
        System.Security.Cryptography.ECParameters ecParams,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
    {
        using var ec = System.Security.Cryptography.ECDsa.Create();
        ec.ImportParameters(ecParams);
        var hashName = MapEcdsaMechanism(mechanism);
        return ec.VerifyData(data, signature, hashName);
    }

    private static (System.Security.Cryptography.HashAlgorithmName, System.Security.Cryptography.RSASignaturePadding)
        MapRsaSignMechanism(Mechanism mechanism) => (CKM)mechanism.Type switch
        {
            CKM.CKM_SHA1_RSA_PKCS   => (System.Security.Cryptography.HashAlgorithmName.SHA1,   System.Security.Cryptography.RSASignaturePadding.Pkcs1),
            CKM.CKM_SHA256_RSA_PKCS => (System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1),
            CKM.CKM_SHA384_RSA_PKCS => (System.Security.Cryptography.HashAlgorithmName.SHA384, System.Security.Cryptography.RSASignaturePadding.Pkcs1),
            CKM.CKM_SHA512_RSA_PKCS => (System.Security.Cryptography.HashAlgorithmName.SHA512, System.Security.Cryptography.RSASignaturePadding.Pkcs1),
            _ => throw new NotSupportedException(
                $"Managed RSA verify is not implemented for mechanism {mechanism.Type}. " +
                "Provide a CKO_PUBLIC_KEY companion on the token to use the native verify path."),
        };

    private static System.Security.Cryptography.HashAlgorithmName MapEcdsaMechanism(Mechanism mechanism)
        => (CKM)mechanism.Type switch
        {
            CKM.CKM_ECDSA_SHA1   => System.Security.Cryptography.HashAlgorithmName.SHA1,
            CKM.CKM_ECDSA_SHA256 => System.Security.Cryptography.HashAlgorithmName.SHA256,
            CKM.CKM_ECDSA_SHA384 => System.Security.Cryptography.HashAlgorithmName.SHA384,
            CKM.CKM_ECDSA_SHA512 => System.Security.Cryptography.HashAlgorithmName.SHA512,
            _ => throw new NotSupportedException(
                $"Managed ECDSA verify is not implemented for mechanism {mechanism.Type}. " +
                "Provide a CKO_PUBLIC_KEY companion on the token to use the native verify path."),
        };
}
