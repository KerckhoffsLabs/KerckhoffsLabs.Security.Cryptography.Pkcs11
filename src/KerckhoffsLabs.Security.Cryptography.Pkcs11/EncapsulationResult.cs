namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Result of <see cref="Pkcs11Key.EncapsulateKey"/> (PKCS#11 v3.2 §5.18.10): the KEM ciphertext to
/// transmit to the holder of the decapsulation key, and the freshly created on-token key wrapping the
/// encapsulated shared secret.
/// </summary>
/// <remarks>
/// <para>
/// The caller owns <see cref="SharedSecret"/> and must dispose it — dispose this result (typically
/// with a <c>using</c> statement), or dispose the key directly after deconstructing. Disposing
/// releases the managed handle only; as with every <see cref="Pkcs11Key"/>, the token object itself
/// is removed by <see cref="Pkcs11Key.Destroy"/> or by the token's session-object lifetime rules.
/// </para>
/// <para>
/// Instances are produced exclusively by <see cref="Pkcs11Key.EncapsulateKey"/>; the constructor is
/// <c>internal</c> because a result fabricated around an arbitrary key would carry a meaningless
/// ciphertext/secret pairing. <c>default(EncapsulationResult)</c> is inert: both properties are
/// <c>null</c> and <see cref="Dispose"/> is a no-op.
/// </para>
/// </remarks>
public readonly record struct EncapsulationResult : IDisposable
{
    /// <summary>
    /// Initializes a result pairing <paramref name="ciphertext"/> with the on-token
    /// <paramref name="sharedSecret"/> key it encapsulates.
    /// </summary>
    internal EncapsulationResult(byte[] ciphertext, Pkcs11Key sharedSecret)
    {
        Ciphertext = ciphertext;
        SharedSecret = sharedSecret;
    }

    /// <summary>
    /// KEM ciphertext to send to the decapsulating party. Not secret; only the holder of the
    /// decapsulation key can recover the shared secret from it.
    /// </summary>
    public byte[] Ciphertext { get; }

    /// <summary>
    /// On-token key wrapping the encapsulated shared secret. Owned by the caller — dispose it (or
    /// this result) when no longer needed.
    /// </summary>
    public Pkcs11Key SharedSecret { get; }

    /// <summary>
    /// Deconstructs into the ciphertext and the shared-secret key. The caller still owns (and must
    /// dispose) <paramref name="sharedSecret"/>.
    /// </summary>
    /// <param name="ciphertext">KEM ciphertext to send to the decapsulating party.</param>
    /// <param name="sharedSecret">On-token key wrapping the encapsulated shared secret.</param>
    public void Deconstruct(out byte[] ciphertext, out Pkcs11Key sharedSecret)
    {
        ciphertext = Ciphertext;
        sharedSecret = SharedSecret;
    }

    /// <summary>
    /// Disposes the <see cref="SharedSecret"/> key handle. Safe on <c>default</c> instances.
    /// </summary>
    public void Dispose() => SharedSecret?.Dispose();
}
