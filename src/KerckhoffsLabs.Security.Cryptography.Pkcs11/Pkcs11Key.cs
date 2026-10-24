using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Handle wrapper over a PKCS#11 key object. Carries the session it belongs to, the
/// private and/or public handles, and the cached identifying metadata (label, ID, key
/// type). Mechanism-level operations (Sign, Verify, Encrypt, Decrypt, Wrap, Unwrap,
/// Derive) delegate through that session.
/// </summary>
/// <remarks>
/// <para>
/// Instances are produced by <see cref="Pkcs11Session"/> factory methods
/// (<c>OpenKey</c>, <c>GenerateKey</c>, <c>ImportKey</c>). A key never owns its session or
/// library: their lifetimes stay with whoever opened them. The <see langword="internal"/> constructor
/// remains visible to the test assembly via <c>InternalsVisibleTo</c>.
/// </para>
/// <para>
/// Asymmetric keys may carry both a private and a public handle or only one. A key opened or
/// found through one half is paired with the other half (same <c>CKA_ID</c> and
/// <c>CKA_KEY_TYPE</c>) the first time an operation needs it, not when it is opened: a listing of
/// many keys then costs no searches for halves nobody uses. A public-only key has
/// <c>privateHandle == ObjectHandle.Invalid</c>; a private-only key on a token without a stored
/// <c>CKO_PUBLIC_KEY</c> companion has <c>publicHandle == ObjectHandle.Invalid</c>.
/// </para>
/// <para>
/// <b>Disposal never destroys token state.</b> <c>Dispose</c> releases the managed wrapper only;
/// <c>Destroy</c> is the only member that calls
/// <c>C_DestroyObject</c>. The two are kept apart deliberately: whether a handle refers to a
/// short-lived session object or to a persistent key is decided at creation by <c>CKA_TOKEN</c> —
/// a runtime template attribute, or the <c>persistOnToken</c> argument of the session factories —
/// so the wrapper cannot tell the two apart. Destroying when it should not is irreversible loss of
/// key material; failing to destroy a session object costs nothing, because PKCS#11 collects those
/// at <c>C_CloseSession</c>. Given that asymmetry, disposal stays inert and destruction stays
/// explicit.
/// </para>
/// </remarks>
public sealed partial class Pkcs11Key : IDisposable
{
    private readonly Pkcs11Session _session;
    // The halves known so far. Read them only through PrivateHandle and PublicHandle, which look up
    // a pending companion first.
    private ObjectHandle _knownPrivateHandle;
    private ObjectHandle _knownPublicHandle;
    private bool _companionPending;
    private readonly CKK _keyType;
    private readonly byte[] _id;
    private bool _disposed;

    internal Pkcs11Key(
        Pkcs11Session session,
        ObjectHandle privateHandle,
        ObjectHandle publicHandle,
        CKK keyType,
        string? label,
        byte[] id,
        bool companionPending = false)
    {
        ArgumentNullException.ThrowIfNull(session);
        if (privateHandle.IsInvalid && publicHandle.IsInvalid)
            throw new ArgumentException(
                "Pkcs11Key must carry at least one valid handle.",
                nameof(privateHandle));

        _session = session;
        _knownPrivateHandle = privateHandle;
        _knownPublicHandle = publicHandle;
        _companionPending = companionPending && (privateHandle.IsInvalid || publicHandle.IsInvalid);
        _keyType = keyType;
        Label = label;
        _id = id ?? [];
    }

    /// <summary>The PKCS#11 key type (e.g. <see cref="CKK.CKK_AES"/>, <see cref="CKK.CKK_RSA"/>).</summary>
    public CKK KeyType => _keyType;

    /// <summary>
    /// The key's size in bits, or <see langword="null"/> when the key type has no single size or the
    /// token doesn't expose it. Read from the token on first access and cached: a key's size never changes.
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    /// <item><see cref="CKK.CKK_EC"/>: the curve's field size from the library's
    /// <see cref="Pkcs11LibraryOptions.CurveCatalog"/>; <see langword="null"/> for a curve it doesn't list
    /// (a coordinate's byte length is not a bit size: prime239v1 is 239 bits in 30 bytes).</item>
    /// <item><see cref="CKK.CKK_RSA"/>: <c>CKA_MODULUS_BITS</c>, else the bit length of <c>CKA_MODULUS</c>.</item>
    /// <item>Secret keys: <c>CKA_VALUE_LEN</c> × 8 when the token exposes it.</item>
    /// <item><see cref="CKK.CKK_DSA"/>: the bit length of <c>CKA_PRIME</c>.</item>
    /// <item>Other asymmetric types (DH, EdDSA, X25519/X448, ML-DSA, ML-KEM, SLH-DSA, ...): <see langword="null"/>.</item>
    /// </list>
    /// </remarks>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GetAttributeValue</c> call; nothing is cached then.</exception>
    public int? KeySize
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            // One int, so a racing reader sees either "not read" or the final answer; both readers
            // compute the same value.
            int bits = _keySizeBits;
            if (bits == KeySizeNotRead)
                _keySizeBits = bits = ReadKeySizeBits() ?? KeySizeUnknown;
            return bits == KeySizeUnknown ? null : bits;
        }
    }

    private const int KeySizeNotRead = -1;
    private const int KeySizeUnknown = 0;
    private int _keySizeBits = KeySizeNotRead;

    private int? ReadKeySizeBits() => _keyType switch
    {
        CKK.CKK_EC => ReadEcKeySizeBits(),
        CKK.CKK_RSA => ReadRsaKeySizeBits(),
        CKK.CKK_DSA => ReadDsaKeySizeBits(),
        CKK.CKK_DH or CKK.CKK_X9_42_DH or CKK.CKK_EC_MONTGOMERY or CKK.CKK_KEA or CKK.CKK_GOSTR3410 => null,
        var t when IsAsymmetricKeyType(t) => null,
        _ => ReadSecretKeySizeBits(),
    };

    // The curve's field size from the library's catalog; null for a curve it doesn't list.
    private int? ReadEcKeySizeBits() => ReadEcCurve()?.FieldSizeBits;

    // CKA_MODULUS_BITS, else the bit length of CKA_MODULUS. Without a public half these are the private one's,
    // so its modulus is kept for decryption.
    private int? ReadRsaKeySizeBits()
    {
        bool privateHalf = PublicHandle.IsInvalid;
        using var attrs = GetAttributeValue(CKA.CKA_MODULUS_BITS, CKA.CKA_MODULUS);
        if (privateHalf && !attrs[1].CannotBeRead)
            KeepRsaModulus(attrs[1].GetValueAsByteArray());
        if (!attrs[0].CannotBeRead)
            return checked((int)attrs[0].GetValueAsUlong());
        return attrs[1].CannotBeRead ? null : BitLength(attrs[1].GetValueAsByteArray());
    }

    // The bit length of CKA_PRIME: PKCS#11 has no CKA_PRIME_BITS (unlike RSA's CKA_MODULUS_BITS).
    private int? ReadDsaKeySizeBits()
    {
        using var attrs = GetAttributeValue(CKA.CKA_PRIME);
        return attrs[0].CannotBeRead ? null : BitLength(attrs[0].GetValueAsByteArray());
    }

    // CKA_VALUE_LEN, in bytes, as bits.
    private int? ReadSecretKeySizeBits()
    {
        using var attrs = GetAttributeValue(CKA.CKA_VALUE_LEN);
        return attrs[0].CannotBeRead ? null : checked((int)attrs[0].GetValueAsUlong() * 8);
    }

    /// <summary>
    /// The curve of an EC key as the library's <see cref="Pkcs11LibraryOptions.CurveCatalog"/> describes it,
    /// read from <c>CKA_EC_PARAMS</c>; <see langword="null"/> when that can't be read, is not a DER-encoded
    /// named-curve OID, or names a curve the catalog doesn't list. Not cached.
    /// </summary>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GetAttributeValue</c> call.</exception>
    internal Pkcs11CurveInfo? ReadEcCurve()
    {
        using var attrs = GetAttributeValue(CKA.CKA_EC_PARAMS);
        if (attrs[0].CannotBeRead)
            return null;
        try
        {
            string oid = Pkcs11ECCurve.FromEcParams(attrs[0].GetValueAsByteArray()).Oid!;
            return _session.Library.CurveCatalog.TryGetByOid(oid, out Pkcs11CurveInfo? curve) ? curve : null;
        }
        catch (ArgumentException)
        {
            return null; // not a DER-encoded named-curve OID
        }
    }

    // Bit length of a big-endian unsigned integer, ignoring leading zero bytes.
    private static int? BitLength(ReadOnlySpan<byte> value)
    {
        value = TrimLeadingZeros(value);
        if (value.IsEmpty)
            return null;
        return (value.Length - 1) * 8 + 32 - System.Numerics.BitOperations.LeadingZeroCount((uint)value[0]);
    }

    // A big-endian unsigned integer without its leading zero bytes; empty for zero.
    private static ReadOnlySpan<byte> TrimLeadingZeros(ReadOnlySpan<byte> value)
    {
        int i = value.IndexOfAnyExcept((byte)0);
        return i < 0 ? [] : value[i..];
    }

    /// <summary>The key's CKA_LABEL, or <see langword="null"/> if not set on the token.</summary>
    public string? Label { get; }

    /// <summary>The key's CKA_ID. Returns an empty span if not set on the token.</summary>
    public ReadOnlySpan<byte> Id => _id;

    /// <summary>
    /// Returns <see langword="true"/> when the token backing this key advertises support for the given
    /// mechanism. Convenience for adapter logic that picks between a combined-hash mechanism and a
    /// hash-then-sign fallback. The answer is probed from the token once and cached on the session.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown if another thread is currently inside an operation on the underlying session. The
    /// probe is a session operation like any other; use a separate session per thread.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when the underlying session has been disposed — including when the answer is already
    /// cached, since a cached capability describes a session that no longer exists.
    /// </exception>
    public bool SupportsMechanism(CKM mechanism) => _session.Core.SupportsMechanism(mechanism);

    /// <summary>
    /// <see cref="SupportsMechanism(CKM)"/>, and the token's C_GetMechanismInfo flags for the mechanism
    /// include every <c>CKF_*</c> operation in <paramref name="requiredFlags"/> when it reports them.
    /// </summary>
    internal bool SupportsMechanism(CKM mechanism, ulong requiredFlags) => _session.Core.SupportsMechanism(mechanism, requiredFlags);

    /// <summary>
    /// Reads the requested attribute values from this key. Uses the public-key handle for
    /// asymmetric keys when it is available (matching the rule <see cref="Encrypt"/> follows), and
    /// the private-key handle otherwise — covering both public-companion key pairs and private-only
    /// keys that carry their own attributes.
    /// </summary>
    /// <param name="types">CKA types to read.</param>
    /// <returns>The attribute values, in the same order as <paramref name="types"/>. Attributes the
    /// token does not expose come back with <see cref="ObjectAttribute.CannotBeRead"/> set. The list
    /// owns the values: dispose it (a <see langword="using"/> will do) to release and zeroize their buffers.</returns>
    /// <exception cref="ObjectDisposedException">Thrown when the key has been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="types"/> is empty.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when the key exposes no readable handle; otherwise propagated from the underlying <c>C_GetAttributeValue</c> call.</exception>
    public ReadOnlyDisposableList<ObjectAttribute> GetAttributeValue(params ReadOnlySpan<CKA> types)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        ObjectHandle handle = (IsAsymmetricKeyType(_keyType) && !PublicHandle.IsInvalid)
            ? PublicHandle
            : PrivateHandle;

        if (handle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.GetAttributeValue (no readable handle)");

        return _session.Core.GetAttributeValue(handle, types);
    }

    /// <summary>
    /// Opens this key's X.509 certificate: the certificate object with the same <c>CKA_ID</c>. Returns
    /// <see langword="null"/> when the key has no <c>CKA_ID</c> or no certificate has it. The caller owns
    /// the returned certificate.
    /// </summary>
    /// <remarks>
    /// The counterpart of <see cref="Pkcs11Certificate.GetPrivateKey"/>; certificates are stored with
    /// their key's id by <see cref="Pkcs11Session.ImportCertificate"/>.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="Pkcs11AmbiguousObjectException">More than one certificate on the token has this key's <c>CKA_ID</c>.</exception>
    /// <exception cref="Pkcs11Exception">Thrown (<see cref="CKR.CKR_ATTRIBUTE_SENSITIVE"/>) if the certificate's <c>CKA_VALUE</c> cannot be read; otherwise propagated from the underlying <c>C_FindObjects</c> or <c>C_GetAttributeValue</c> call.</exception>
    public Pkcs11Certificate? GetCertificate()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _session.OpenCertificateById(_id);
    }

    /// <summary>Internal accessor for the session this key belongs to.</summary>
    internal Pkcs11Session Session => _session;

    /// <summary>
    /// Internal accessor for the private handle. <see cref="ObjectHandle.Invalid"/> for public-only keys.
    /// Looks up a pending private companion first.
    /// </summary>
    internal ObjectHandle PrivateHandle
    {
        get
        {
            if (_knownPrivateHandle.IsInvalid)
                ResolveCompanion();
            return _knownPrivateHandle;
        }
    }

    /// <summary>
    /// Internal accessor for the public handle. <see cref="ObjectHandle.Invalid"/> when no companion
    /// exists and synthesis is unavailable. Looks up a pending public companion first.
    /// </summary>
    internal ObjectHandle PublicHandle
    {
        get
        {
            if (_knownPublicHandle.IsInvalid)
                ResolveCompanion();
            return _knownPublicHandle;
        }
    }

    /// <summary>
    /// Searches for the missing half of the pair, once, the first time it is needed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The search runs under the session's lease, and the pending flag is cleared only after it
    /// returns. Clearing it first would let a second thread see "no companion" mid-search and quietly
    /// take <see cref="Verify"/>'s managed fallback; under the lease that thread gets the session's
    /// concurrent-use error instead, as for any other call. A search that throws leaves the flag set,
    /// so the next use searches again rather than settling for "none".
    /// </para>
    /// <para>
    /// The lease is reentrant on its own thread, so the search's own <c>C_FindObjects*</c> calls take it
    /// again without contention.
    /// </para>
    /// </remarks>
    private void ResolveCompanion()
    {
        if (!Volatile.Read(ref _companionPending))
            return;

        using var _ = _session.Core.AcquireExclusive();
        if (!_companionPending)
            return;

        if (_knownPublicHandle.IsInvalid)
            _knownPublicHandle = _session.FindCompanion(CKO.CKO_PUBLIC_KEY, _id, _keyType);
        else
            _knownPrivateHandle = _session.FindCompanion(CKO.CKO_PRIVATE_KEY, _id, _keyType);

        Volatile.Write(ref _companionPending, false);
    }

    /// <summary>
    /// Checks that this key has the token object a mechanism parameter asks for, so a parameter type
    /// can reject an unusable key when it is constructed rather than when the operation runs.
    /// </summary>
    /// <param name="part">Which object the parameter refers to.</param>
    /// <param name="paramName">The parameter-type argument the key was passed as, for the exception.</param>
    /// <exception cref="ArgumentException">The key has no object of that kind — for example a public
    /// part requested from a secret key, or a private part from a public-only key.</exception>
    internal void EnsureHasParameterHandle(KeyHandlePart part, string paramName) =>
        _ = SelectParameterHandle(part, paramName);

    /// <summary>
    /// Resolves the handle a mechanism parameter carries for this key, at the moment the parameter is
    /// marshalled for <paramref name="session"/>.
    /// </summary>
    /// <remarks>
    /// A handle only means something to the session and login it came from, so a key from another
    /// session is refused rather than sent: its number could name an unrelated object — or nothing —
    /// in the calling session.
    /// </remarks>
    /// <param name="session">The session performing the call.</param>
    /// <param name="part">Which object the parameter refers to.</param>
    /// <param name="paramName">The parameter-type argument the key was passed as, for the exception.</param>
    /// <exception cref="ObjectDisposedException">The key has been disposed.</exception>
    /// <exception cref="ArgumentException">The key belongs to a different session, or has no object
    /// of the requested kind.</exception>
    internal ObjectHandle ResolveParameterHandle(Pkcs11SessionCore session, KeyHandlePart part, string paramName)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!ReferenceEquals(_session.Core, session))
            throw new ArgumentException(
                "The key belongs to a different session than the operation. Mechanism parameters can only " +
                "reference keys from the session that performs the call.",
                paramName);
        return SelectParameterHandle(part, paramName);
    }

    private ObjectHandle SelectParameterHandle(KeyHandlePart part, string paramName)
    {
        switch (part)
        {
            case KeyHandlePart.Private:
                if (PrivateHandle.IsInvalid)
                    throw new ArgumentException(
                        "The key has no private-key or secret-key object on the token; this parameter needs one.",
                        paramName);
                return PrivateHandle;

            case KeyHandlePart.Public:
                if (PublicHandle.IsInvalid)
                    throw new ArgumentException(
                        "The key has no public-key object on the token (a secret key never has one); this " +
                        "parameter needs one.",
                        paramName);
                return PublicHandle;

            default:
                throw new ArgumentOutOfRangeException(nameof(part), part, "Not a defined KeyHandlePart member.");
        }
    }

    /// <summary>
    /// Returns the synthesized RSA public parameters for this key when its public side
    /// is reachable via attributes on the private-key object. Returns <see langword="null"/> if
    /// the key already has a real <see cref="PublicHandle"/> (caller should use that
    /// path instead), or when synthesis is unavailable (non-RSA key type, or
    /// CKA_MODULUS/CKA_PUBLIC_EXPONENT marked sensitive).
    /// </summary>
    internal System.Security.Cryptography.RSAParameters? GetSynthesizedRsaParameters()
    {
        if (_keyType != CKK.CKK_RSA) return null;
        if (!PublicHandle.IsInvalid) return null;
        if (PrivateHandle.IsInvalid) return null;

        return PublicKeySynthesis.TrySynthesizeRsa(_session.Core, PrivateHandle);
    }

    /// <summary>
    /// Returns the synthesized EC public parameters when this key is an EC private-only
    /// key with readable CKA_EC_POINT + CKA_EC_PARAMS. Returns <see langword="null"/> when the
    /// key is non-EC, a real public handle exists (caller should use that path), or
    /// CKA_EC_POINT is sensitive/missing on the private object.
    /// </summary>
    internal System.Security.Cryptography.ECParameters? GetSynthesizedEcParameters()
    {
        if (_keyType != CKK.CKK_EC) return null;
        if (!PublicHandle.IsInvalid) return null;
        if (PrivateHandle.IsInvalid) return null;
        return PublicKeySynthesis.TrySynthesizeEc(_session.Core, PrivateHandle);
    }

    /// <summary>
    /// Permanently removes the underlying object(s) from the token via <c>C_DestroyObject</c>.
    /// For a key pair this destroys both the private and public objects.
    /// </summary>
    /// <remarks>
    /// This is distinct from <see cref="Dispose"/>: <c>Dispose</c> only releases this wrapper
    /// and leaves the token object intact, whereas
    /// <c>Destroy</c> erases the key material from the token. The token enforces its own
    /// permissions — destroying a read-only object, or one created with
    /// <c>CKA_DESTROYABLE = false</c>, fails with a <see cref="Exceptions.Pkcs11Exception"/>
    /// (typically <c>CKR_ACTION_PROHIBITED</c>). After a successful destroy the handles are stale;
    /// still <see cref="Dispose"/> the key to release the wrapper.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">The key has already been disposed.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_DestroyObject</c> call — for example <see cref="CKR.CKR_ACTION_PROHIBITED"/> when the object is not destroyable.</exception>
    public void Destroy()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!PrivateHandle.IsInvalid) _session.Core.DestroyObject(PrivateHandle);
        if (!PublicHandle.IsInvalid) _session.Core.DestroyObject(PublicHandle);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Signs <paramref name="data"/> using the given mechanism. Requires the key to
    /// carry a private handle (symmetric keys are sign-capable too).
    /// </summary>
    /// <param name="mechanism">The signing mechanism.</param>
    /// <param name="data">The data to sign.</param>
    /// <returns>The signature bytes.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is insecure-by-default and the session's <see cref="Pkcs11Session.Policy"/> refuses it.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when the key carries no private handle; otherwise propagated from the underlying <c>C_Sign</c> call.</exception>
    public byte[] Sign(Mechanism mechanism, ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);

        if (PrivateHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Sign (no private handle)");

        return _session.Core.Sign(mechanism, PrivateHandle, data);
    }

    /// <summary>
    /// Verifies <paramref name="signature"/> over <paramref name="data"/> using the
    /// given mechanism. A secret key verifies with its own handle. An asymmetric key uses the real
    /// public handle when present, and falls back to managed verification via the synthesized
    /// RSA/EC public parameters when no real handle exists.
    /// </summary>
    /// <returns><see langword="true"/> if the signature is valid, <see langword="false"/> if not.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is insecure-by-default and the session's <see cref="Pkcs11Session.Policy"/> refuses it.</exception>
    /// <exception cref="NotSupportedException">Thrown when the managed verification fallback is taken (no public handle on the token) and <paramref name="mechanism"/> has no managed RSA/ECDSA equivalent.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when no public handle exists and managed synthesis is unavailable; otherwise propagated from the underlying <c>C_Verify</c> call.</exception>
    public bool Verify(Mechanism mechanism, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);

        // A secret key (HMAC, CMAC) verifies with the same object it signs with: it has no public half.
        if (!IsAsymmetricKeyType(_keyType) && !PrivateHandle.IsInvalid)
            return _session.Core.Verify(mechanism, PrivateHandle, data, signature);

        // Prefer the real public handle.
        if (!PublicHandle.IsInvalid)
            return _session.Core.Verify(mechanism, PublicHandle, data, signature);

        // Fall back to managed verify via synthesized public parameters. No session call happens on this
        // path, so the session policy is consulted here — the same verdict the token path gets from
        // the session's own check.
        _session.Enforce(new MechanismUseRequest(mechanism, CryptoOperation.Verify));

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
    /// Signs a digest the caller computed with RSASSA-PKCS1-v1_5, judged by the session's policy as the
    /// combined mechanism for <paramref name="hash"/>; see <see cref="Pkcs11SessionCore.SignPkcs1Digest"/>.
    /// </summary>
    internal byte[] SignPkcs1Digest(System.Security.Cryptography.HashAlgorithmName hash, ReadOnlySpan<byte> digest)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (PrivateHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.SignPkcs1Digest (no private handle)");

        return _session.Core.SignPkcs1Digest(hash, PrivateHandle, digest);
    }

    /// <summary>
    /// Verifies an RSASSA-PKCS1-v1_5 signature over a digest the caller computed, under the policy's verdict
    /// on the combined mechanism for <paramref name="hash"/>. Uses the public handle when present, otherwise
    /// the synthesized public parameters, as <see cref="Verify"/> does.
    /// </summary>
    internal bool VerifyPkcs1Digest(System.Security.Cryptography.HashAlgorithmName hash, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!PublicHandle.IsInvalid)
            return _session.Core.VerifyPkcs1Digest(hash, PublicHandle, digest, signature);

        // No session call happens on this path, so the policy is asked here, as Verify asks it.
        (CKM scheme, _) = Pkcs1DigestInfo.Encode(hash, digest);
        _session.Enforce(new MechanismUseRequest(new Mechanism(scheme), CryptoOperation.Verify));

        if (_keyType == CKK.CKK_RSA && GetSynthesizedRsaParameters() is { } rsaParams)
        {
            using var rsa = System.Security.Cryptography.RSA.Create();
            rsa.ImportParameters(rsaParams);
            return rsa.VerifyHash(digest, signature, hash, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        }

        throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
            "Pkcs11Key.VerifyPkcs1Digest (no public handle and synthesis unavailable)");
    }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> using this key. Symmetric keys use the
    /// single handle; asymmetric public-side encryption (RSA-OAEP / RSA-PKCS) uses the
    /// public handle.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is insecure-by-default and the session's <see cref="Pkcs11Session.Policy"/> refuses it.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when the required public or symmetric handle is unavailable; otherwise propagated from the underlying <c>C_Encrypt</c> call.</exception>
    public byte[] Encrypt(Mechanism mechanism, ReadOnlySpan<byte> plaintext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);

        ObjectHandle handle = IsAsymmetricKeyType(_keyType)
            ? PublicHandle
            : PrivateHandle;

        if (handle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Encrypt (handle unavailable)");

        return _session.Core.Encrypt(mechanism, handle, plaintext);
    }

    /// <summary>
    /// Decrypts <paramref name="ciphertext"/> using this key. Symmetric uses the single
    /// handle; asymmetric uses the private handle.
    /// </summary>
    /// <remarks>
    /// With <see cref="CKM.CKM_RSA_PKCS"/> or <see cref="CKM.CKM_RSA_PKCS_OAEP"/>, a ciphertext this RSA key cannot
    /// have produced never reaches the token, which might otherwise answer it with a plaintext: as for the BCL's
    /// own RSA, it must be the modulus's length and its big-endian value less than the modulus.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is insecure-by-default and the session's <see cref="Pkcs11Session.Policy"/> refuses it.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown, with an RSA PKCS#1 v1.5 or OAEP mechanism, if <paramref name="ciphertext"/> is not the length of the key's modulus, or its value is not less than the modulus.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when the key carries no private handle; otherwise propagated from the underlying <c>C_Decrypt</c> call.</exception>
    public byte[] Decrypt(Mechanism mechanism, ReadOnlySpan<byte> ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);

        if (PrivateHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Decrypt (no private handle)");

        return _session.Core.Decrypt(mechanism, PrivateHandle, ciphertext, RsaCiphertextCheckFor(mechanism));
    }

    /// <summary>
    /// True when the loaded PKCS#11 library exposes the v3.0 message-based AEAD API.
    /// When false, callers should use <see cref="Encrypt"/> / <see cref="Decrypt"/>
    /// with the legacy CK_GCM_PARAMS / CK_CCM_PARAMS / CK_SALSA20_CHACHA20_POLY1305_PARAMS.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    public bool SupportsMessageApi
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _session.Core.SupportsMessageApi;
        }
    }

    /// <summary>
    /// One-shot AEAD encrypt using the v3.0 message-based API. The per-message tag
    /// is filled into <paramref name="messageParams"/>; read it back via the wrapper's
    /// <c>CopyTagTo</c> / <c>CopyMacTo</c> after this call.
    /// </summary>
    /// <param name="mechanism">AEAD mechanism (mechanism parameter is empty in message mode).</param>
    /// <param name="messageParams">Per-message parameters (nonce + tag buffer).</param>
    /// <param name="associatedData">Optional AAD.</param>
    /// <param name="plaintext">Bytes to encrypt.</param>
    /// <returns>Ciphertext (tag is in <paramref name="messageParams"/>).</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> or <paramref name="messageParams"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is insecure-by-default and the session's <see cref="Pkcs11Session.Policy"/> refuses it.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when the required public or symmetric handle is unavailable; otherwise propagated from the underlying <c>C_EncryptMessage</c> call.</exception>
    public byte[] MessageEncrypt(
        Mechanism mechanism,
        MechanismParameters messageParams,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> plaintext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(messageParams);

        ObjectHandle handle = IsAsymmetricKeyType(_keyType) ? PublicHandle : PrivateHandle;
        if (handle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.MessageEncrypt (handle unavailable)");

        return _session.Core.MessageEncrypt(mechanism, handle, messageParams, associatedData, plaintext);
    }

    /// <summary>
    /// One-shot AEAD decrypt using the v3.0 message-based API. Supply the tag through
    /// <paramref name="messageParams"/> constructed via its <c>ForDecrypt</c> factory.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> or <paramref name="messageParams"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is insecure-by-default and the session's <see cref="Pkcs11Session.Policy"/> refuses it.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when the key carries no private handle; otherwise propagated from the underlying <c>C_DecryptMessage</c> call — notably <see cref="CKR.CKR_AEAD_DECRYPT_FAILED"/> when authentication fails.</exception>
    public byte[] MessageDecrypt(
        Mechanism mechanism,
        MechanismParameters messageParams,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(messageParams);

        if (PrivateHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.MessageDecrypt (no private handle)");

        return _session.Core.MessageDecrypt(mechanism, PrivateHandle, messageParams, associatedData, ciphertext);
    }

    /// <summary>
    /// Wraps <paramref name="targetKey"/> with this key. This key is the wrapper; the
    /// target's private (or symmetric) handle is consumed by the wrap operation.
    /// </summary>
    /// <param name="mechanism">The wrap mechanism (e.g. <see cref="CKM.CKM_AES_KEY_WRAP"/>).</param>
    /// <param name="targetKey">The key being wrapped. Must carry a private/symmetric handle.</param>
    /// <returns>The wrapped key bytes — opaque blob to be transported / stored.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> or <paramref name="targetKey"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is insecure-by-default and the session's <see cref="Pkcs11Session.Policy"/> refuses it.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when this key's wrapping handle or <paramref name="targetKey"/>'s handle is unavailable; otherwise propagated from the underlying <c>C_WrapKey</c> call.</exception>
    public byte[] Wrap(Mechanism mechanism, Pkcs11Key targetKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(targetKey);

        ObjectHandle wrapHandle = IsAsymmetricKeyType(_keyType) ? PublicHandle : PrivateHandle;
        if (wrapHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Wrap (wrapping-key handle unavailable)");

        ObjectHandle targetHandle = targetKey.PrivateHandle.IsInvalid
            ? targetKey.PublicHandle
            : targetKey.PrivateHandle;
        if (targetHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Wrap (target-key handle unavailable)");

        return _session.Core.WrapKey(mechanism, wrapHandle, targetHandle);
    }

    /// <summary>
    /// Unwraps the byte blob <paramref name="wrappedBytes"/> using this key as the
    /// unwrapping key, into a new on-token object described by
    /// <paramref name="template"/>. Symmetric uses the single handle; asymmetric
    /// uses the private handle (unwrapping is a decrypt-shaped operation).
    /// </summary>
    /// <remarks>
    /// As for <see cref="Decrypt"/>, with <see cref="CKM.CKM_RSA_PKCS"/> or <see cref="CKM.CKM_RSA_PKCS_OAEP"/> a
    /// wrapped key this RSA key cannot have produced never reaches the token.
    /// </remarks>
    /// <returns>A new <see cref="Pkcs11Key"/> wrapping the unwrapped object.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> or <paramref name="template"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is insecure-by-default, or <paramref name="template"/> requests an extractable or non-sensitive key, unless the session's <see cref="Pkcs11Session.Policy"/> permits it.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown, with an RSA PKCS#1 v1.5 or OAEP mechanism, if <paramref name="wrappedBytes"/> is not the length of the key's modulus, or its value is not less than the modulus.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when the key carries no private handle; otherwise propagated from the underlying <c>C_UnwrapKey</c> call.</exception>
    public Pkcs11Key Unwrap(Mechanism mechanism, ReadOnlySpan<byte> wrappedBytes, ObjectTemplate template)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(template);

        if (PrivateHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Unwrap (no private handle)");

        ObjectHandle resulting = _session.Core.UnwrapKey(
            mechanism, PrivateHandle, wrappedBytes, [.. template.Attributes], RsaCiphertextCheckFor(mechanism));

        return _session.HydrateExistingHandleAsKey(resulting);
    }

    // What an RSA ciphertext is held to. Null until first needed; read and written with Volatile, so a thread
    // racing the first write sees null or the whole value. A key object's CKA_MODULUS cannot be modified.
    private RsaModulus? _rsaModulus;

    // Value is the modulus, big-endian without leading zero bytes, or null when only its byte Length is known.
    // A Length of zero knows nothing.
    private sealed record RsaModulus(byte[]? Value, int Length)
    {
        public static readonly RsaModulus Unknown = new(null, 0);
    }

    // The check that refuses, as the BCL's own RSA does, a ciphertext an RSA key cannot have produced under
    // CKM_RSA_PKCS or CKM_RSA_PKCS_OAEP: one that is not the modulus's length, or whose big-endian value is not
    // less than the modulus. Some tokens answer one with a plaintext (Wycheproof rsa_pkcs1_2048_test.json tcIds
    // 30, 32 and 35). Null for any other key type or mechanism. The core calls it once the policy has allowed
    // the mechanism, so a refused PKCS#1 v1.5 is refused as such, and the token is not read for it.
    private Pkcs11SessionCore.InputCheck? RsaCiphertextCheckFor(Mechanism mechanism) =>
        _keyType == CKK.CKK_RSA && mechanism.Type is CKM.CKM_RSA_PKCS or CKM.CKM_RSA_PKCS_OAEP
            ? ThrowIfNotRsaCiphertext
            : null;

    // Equal-length big-endian values compare as their bytes do. Neither is secret, so the comparison need not
    // run in constant time.
    private void ThrowIfNotRsaCiphertext(ReadOnlySpan<byte> data)
    {
        RsaModulus modulus = Volatile.Read(ref _rsaModulus) ?? ReadRsaModulus();
        if (modulus.Length == 0)
            return;
        if (data.Length != modulus.Length)
            throw new System.Security.Cryptography.CryptographicException(
                "The length of the data to decrypt is not valid for the size of this key.");
        if (modulus.Value is not null && data.SequenceCompareTo(modulus.Value) >= 0)
            throw new System.Security.Cryptography.CryptographicException(
                "The data to decrypt is not less than the key's modulus.");
    }

    // The private half's CKA_MODULUS: that half is the one that decrypts, and a public half found by CKA_ID
    // could be another key's. A private key need not expose it; then KeySize, best-effort, still fixes the
    // length, and with neither the ciphertext goes to the token unchecked, as it did before. A modulus of
    // zero throws CKR_ATTRIBUTE_VALUE_INVALID rather than refusing every ciphertext.
    private RsaModulus ReadRsaModulus()
    {
        using (var attrs = _session.Core.GetAttributeValue(PrivateHandle, [CKA.CKA_MODULUS]))
        {
            if (!attrs[0].CannotBeRead)
                return KeepRsaModulus(attrs[0].GetValueAsByteArray())
                    ?? throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_VALUE_INVALID, "Pkcs11Key.Decrypt (RSA modulus is zero)");
        }

        RsaModulus fromSize = KeySize is int bits ? new(null, (bits + 7) / 8) : RsaModulus.Unknown;
        Volatile.Write(ref _rsaModulus, fromSize);
        return fromSize;
    }

    // Keeps a non-zero modulus; null for zero.
    private RsaModulus? KeepRsaModulus(ReadOnlySpan<byte> value)
    {
        value = TrimLeadingZeros(value);
        if (value.IsEmpty)
            return null;
        var modulus = new RsaModulus(value.ToArray(), value.Length);
        Volatile.Write(ref _rsaModulus, modulus);
        return modulus;
    }

    /// <summary>
    /// Encapsulates a fresh shared-secret key against this key's public handle
    /// (PKCS#11 v3.2 §5.18.10). Typically used with <see cref="CKM.CKM_ML_KEM"/>.
    /// </summary>
    /// <param name="mechanism">Encapsulation mechanism.</param>
    /// <param name="sharedSecretTemplate">Template applied to the freshly-derived shared-secret key.</param>
    /// <param name="expectedCiphertextLen">
    /// When &gt; 0, the exact ciphertext length is already known (e.g. fixed by the ML-KEM parameter
    /// set), letting the token fill a pre-sized buffer in a single call instead of a NULL-buffer length
    /// probe — required for tokens (SoftHSM) that do not honour the probe for <c>C_EncapsulateKey</c>.
    /// </param>
    /// <returns>
    /// An <see cref="EncapsulationResult"/> pairing the ciphertext to send to the decapsulator with
    /// the on-token <see cref="Pkcs11Key"/> wrapping the shared secret. The caller owns the result's
    /// <see cref="EncapsulationResult.SharedSecret"/> — dispose the result (or the key) when done.
    /// </returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> or <paramref name="sharedSecretTemplate"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is insecure-by-default, or <paramref name="sharedSecretTemplate"/> requests an extractable or non-sensitive key, unless the session's <see cref="Pkcs11Session.Policy"/> permits it.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when no public handle is reachable, or <see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> from the underlying <c>C_EncapsulateKey</c> call on pre-v3.2 libraries.</exception>
    public EncapsulationResult EncapsulateKey(
        Mechanism mechanism,
        ObjectTemplate sharedSecretTemplate,
        int expectedCiphertextLen = 0)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(sharedSecretTemplate);

        if (PublicHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.EncapsulateKey (no public handle)");

        var (ct, sharedHandle) = _session.Core.EncapsulateKey(
            mechanism, PublicHandle, [.. sharedSecretTemplate.Attributes], expectedCiphertextLen);
        return new EncapsulationResult(ct, _session.HydrateExistingHandleAsKey(sharedHandle));
    }

    /// <summary>
    /// Decapsulates the shared-secret key from <paramref name="ciphertext"/> using this
    /// key's private handle (PKCS#11 v3.2 §5.18.11).
    /// </summary>
    /// <returns>An on-token <see cref="Pkcs11Key"/> wrapping the recovered shared secret.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> or <paramref name="sharedSecretTemplate"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if <paramref name="mechanism"/> is insecure-by-default, or <paramref name="sharedSecretTemplate"/> requests an extractable or non-sensitive key, unless the session's <see cref="Pkcs11Session.Policy"/> permits it.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when no private handle is reachable, or <see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> from the underlying <c>C_DecapsulateKey</c> call on pre-v3.2 libraries.</exception>
    public Pkcs11Key DecapsulateKey(
        Mechanism mechanism,
        ReadOnlySpan<byte> ciphertext,
        ObjectTemplate sharedSecretTemplate)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(sharedSecretTemplate);

        if (PrivateHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.DecapsulateKey (no private handle)");

        ObjectHandle sharedHandle = _session.Core.DecapsulateKey(
            mechanism, PrivateHandle, ciphertext, [.. sharedSecretTemplate.Attributes]);
        return _session.HydrateExistingHandleAsKey(sharedHandle);
    }

    /// <summary>
    /// Derives a new key from this key. Secure defaults (<c>CKA_SENSITIVE=true</c> /
    /// <c>CKA_EXTRACTABLE=false</c>) are applied to the result template; deriving an extractable or
    /// non-sensitive key requires a policy that permits reading key material off the token, e.g. <c>Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)</c>. Symmetric
    /// uses the single handle; asymmetric uses the private handle (e.g. ECDH derives from the
    /// local private key — the peer's public point travels as a mechanism parameter, not a handle).
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the key has been disposed.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="mechanism"/> or <paramref name="template"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptoPolicyViolationException">Thrown if the result <paramref name="template"/> requests an extractable or non-sensitive key, or <paramref name="mechanism"/> is insecure-by-default, unless the session's <see cref="Pkcs11Session.Policy"/> permits it.</exception>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_OBJECT_HANDLE_INVALID"/> when the key carries no private handle; otherwise propagated from the underlying <c>C_DeriveKey</c> call.</exception>
    public Pkcs11Key Derive(Mechanism mechanism, ObjectTemplate template)
        => DeriveCore(mechanism, template);

    private Pkcs11Key DeriveCore(Mechanism mechanism, ObjectTemplate template)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(template);

        if (PrivateHandle.IsInvalid)
            throw Pkcs11Exception.Create(CKR.CKR_OBJECT_HANDLE_INVALID,
                "Pkcs11Key.Derive (no private handle)");

        ObjectHandle resulting = _session.Core.DeriveKey(
            mechanism, PrivateHandle, [.. template.Attributes]);

        // SP800-108 sibling keys: the params object absorbed their raw handles during the call
        // above; turn them into usable Pkcs11Key instances now, while the session is at hand.
        if (mechanism.Parameters is CkmSp800108KdfParams sp800108)
            sp800108.HydrateDerivedKeys(_session);

        return _session.HydrateExistingHandleAsKey(resulting);
    }

    private static bool IsAsymmetricKeyType(CKK keyType) => keyType switch
    {
        CKK.CKK_RSA or CKK.CKK_DSA or CKK.CKK_EC or CKK.CKK_EC_EDWARDS
            or CKK.CKK_ML_KEM or CKK.CKK_ML_DSA or CKK.CKK_SLH_DSA => true,
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

        // Raw CKM_ECDSA signs a pre-computed digest, so the input IS the hash — verify it directly.
        // The token emits an IEEE P1363 (r‖s) signature, which is ECDsa.VerifyHash's default format.
        if (mechanism.Type == CKM.CKM_ECDSA)
            return ec.VerifyHash(data, signature);

        var hashName = MapEcdsaMechanism(mechanism);
        return ec.VerifyData(data, signature, hashName);
    }

    private static (System.Security.Cryptography.HashAlgorithmName, System.Security.Cryptography.RSASignaturePadding)
        MapRsaSignMechanism(Mechanism mechanism) => mechanism.Type switch
        {
            CKM.CKM_SHA1_RSA_PKCS => (System.Security.Cryptography.HashAlgorithmName.SHA1, System.Security.Cryptography.RSASignaturePadding.Pkcs1),
            CKM.CKM_SHA256_RSA_PKCS => (System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1),
            CKM.CKM_SHA384_RSA_PKCS => (System.Security.Cryptography.HashAlgorithmName.SHA384, System.Security.Cryptography.RSASignaturePadding.Pkcs1),
            CKM.CKM_SHA512_RSA_PKCS => (System.Security.Cryptography.HashAlgorithmName.SHA512, System.Security.Cryptography.RSASignaturePadding.Pkcs1),
            CKM.CKM_SHA3_256_RSA_PKCS => (System.Security.Cryptography.HashAlgorithmName.SHA3_256, System.Security.Cryptography.RSASignaturePadding.Pkcs1),
            CKM.CKM_SHA3_384_RSA_PKCS => (System.Security.Cryptography.HashAlgorithmName.SHA3_384, System.Security.Cryptography.RSASignaturePadding.Pkcs1),
            CKM.CKM_SHA3_512_RSA_PKCS => (System.Security.Cryptography.HashAlgorithmName.SHA3_512, System.Security.Cryptography.RSASignaturePadding.Pkcs1),
            // PSS: RSASignaturePadding.Pss uses a digest-length salt, matching the salt the
            // RSA-PSS sign path (Pkcs11MechanismMap.RsaPssSign) defaults to.
            CKM.CKM_SHA1_RSA_PKCS_PSS => (System.Security.Cryptography.HashAlgorithmName.SHA1, System.Security.Cryptography.RSASignaturePadding.Pss),
            CKM.CKM_SHA256_RSA_PKCS_PSS => (System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pss),
            CKM.CKM_SHA384_RSA_PKCS_PSS => (System.Security.Cryptography.HashAlgorithmName.SHA384, System.Security.Cryptography.RSASignaturePadding.Pss),
            CKM.CKM_SHA512_RSA_PKCS_PSS => (System.Security.Cryptography.HashAlgorithmName.SHA512, System.Security.Cryptography.RSASignaturePadding.Pss),
            CKM.CKM_SHA3_256_RSA_PKCS_PSS => (System.Security.Cryptography.HashAlgorithmName.SHA3_256, System.Security.Cryptography.RSASignaturePadding.Pss),
            CKM.CKM_SHA3_384_RSA_PKCS_PSS => (System.Security.Cryptography.HashAlgorithmName.SHA3_384, System.Security.Cryptography.RSASignaturePadding.Pss),
            CKM.CKM_SHA3_512_RSA_PKCS_PSS => (System.Security.Cryptography.HashAlgorithmName.SHA3_512, System.Security.Cryptography.RSASignaturePadding.Pss),
            // Raw CKM_RSA_PKCS / CKM_RSA_X_509 carry the hash inside a DigestInfo, so there is no
            // mechanism-level hash to map to a managed VerifyData call. Use a CKO_PUBLIC_KEY companion.
            _ => throw new NotSupportedException(
                $"Managed RSA verify is not implemented for mechanism {mechanism.Type}. " +
                "Provide a CKO_PUBLIC_KEY companion on the token to use the native verify path."),
        };

    private static System.Security.Cryptography.HashAlgorithmName MapEcdsaMechanism(Mechanism mechanism)
        => mechanism.Type switch
        {
            CKM.CKM_ECDSA_SHA1 => System.Security.Cryptography.HashAlgorithmName.SHA1,
            CKM.CKM_ECDSA_SHA256 => System.Security.Cryptography.HashAlgorithmName.SHA256,
            CKM.CKM_ECDSA_SHA384 => System.Security.Cryptography.HashAlgorithmName.SHA384,
            CKM.CKM_ECDSA_SHA512 => System.Security.Cryptography.HashAlgorithmName.SHA512,
            CKM.CKM_ECDSA_SHA3_256 => System.Security.Cryptography.HashAlgorithmName.SHA3_256,
            CKM.CKM_ECDSA_SHA3_384 => System.Security.Cryptography.HashAlgorithmName.SHA3_384,
            CKM.CKM_ECDSA_SHA3_512 => System.Security.Cryptography.HashAlgorithmName.SHA3_512,
            _ => throw new NotSupportedException(
                $"Managed ECDSA verify is not implemented for mechanism {mechanism.Type}. " +
                "Provide a CKO_PUBLIC_KEY companion on the token to use the native verify path."),
        };
}
