namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// Which of a <see cref="Pkcs11Key"/>'s token objects a mechanism parameter refers to. A key pair is
/// two PKCS#11 objects with two handles; a secret key is one.
/// </summary>
public enum KeyHandlePart
{
    /// <summary>The private-key object of a key pair, or the single object of a secret key.</summary>
    Private,

    /// <summary>The public-key object of a key pair. Not valid for a secret key.</summary>
    Public,
}
