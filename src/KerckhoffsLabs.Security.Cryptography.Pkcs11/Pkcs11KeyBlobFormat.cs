namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// The encodings <see cref="Pkcs11Key.Export"/> writes. Every format carries the public half only: a
/// token key's private material never leaves the token through <see cref="Pkcs11Key.Export"/>
/// (<see cref="Pkcs11Key.Wrap"/> is the path for an extractable key).
/// </summary>
public enum Pkcs11KeyBlobFormat
{
    /// <summary>
    /// X.509 <c>SubjectPublicKeyInfo</c>, DER (RFC 5280 §4.1.2.7): the algorithm, its parameters and the
    /// public key. What <see cref="System.Security.Cryptography.AsymmetricAlgorithm.ImportSubjectPublicKeyInfo"/> reads.
    /// </summary>
    SubjectPublicKeyInfo = 0,

    /// <summary>
    /// The algorithm's own public-key encoding, without an algorithm identifier. EC: the uncompressed
    /// point <c>0x04 ‖ X ‖ Y</c>. Ed25519 / Ed448 / X25519 / X448: the RFC 8032 / RFC 7748 key bytes.
    /// </summary>
    RawPublicKey = 1,
}
