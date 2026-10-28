using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

/// <summary>
/// The in-process <see cref="ManagedSoftToken"/> as an <see cref="IPkcs11Backend"/>, so the backend-agnostic
/// test cases run on it too. Tests using it belong to <c>[Collection(FakeModuleCollection.Name)]</c> and
/// dispose it.
/// </summary>
/// <remarks>
/// <see cref="Supports"/> answers for the mechanisms the token implements, not the shorter list its
/// <c>C_GetMechanismList</c> advertises: the token predates most of its mechanisms' entries there. The token
/// computes with the BCL, so a mechanism counts only where the host BCL has the algorithm: SHA-3,
/// ChaCha20-Poly1305 and the post-quantum signatures need OpenSSL 3 or a recent Windows, and macOS has no
/// AES-CCM.
/// </remarks>
internal sealed class ManagedBackend : IPkcs11Backend, IDisposable
{
    private static readonly HashSet<CKM> Implemented = HostImplemented();

    private static HashSet<CKM> HostImplemented()
    {
        HashSet<CKM> mechanisms =
        [
            CKM.CKM_SHA256, CKM.CKM_SHA384, CKM.CKM_SHA512,
            CKM.CKM_SHA256_HMAC, CKM.CKM_SHA384_HMAC, CKM.CKM_SHA512_HMAC,
            CKM.CKM_GENERIC_SECRET_KEY_GEN, CKM.CKM_AES_KEY_GEN,
            CKM.CKM_AES_CBC, CKM.CKM_AES_CBC_PAD, CKM.CKM_AES_CFB8, CKM.CKM_AES_CFB128, CKM.CKM_AES_KEY_WRAP_KWP,
            CKM.CKM_HKDF_DERIVE, CKM.CKM_SP800_108_COUNTER_KDF,
            CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_RSA_PKCS_OAEP, CKM.CKM_RSA_PKCS_PSS,
            CKM.CKM_SHA256_RSA_PKCS, CKM.CKM_SHA384_RSA_PKCS, CKM.CKM_SHA512_RSA_PKCS,
            CKM.CKM_SHA256_RSA_PKCS_PSS, CKM.CKM_SHA384_RSA_PKCS_PSS, CKM.CKM_SHA512_RSA_PKCS_PSS,
            CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA, CKM.CKM_ECDSA_SHA256, CKM.CKM_ECDSA_SHA384, CKM.CKM_ECDSA_SHA512,
            CKM.CKM_ECDH1_DERIVE,
        ];
        AddIf(mechanisms, SHA3_256.IsSupported, CKM.CKM_SHA3_256, CKM.CKM_SHA3_256_RSA_PKCS, CKM.CKM_SHA3_256_RSA_PKCS_PSS);
        AddIf(mechanisms, SHA3_384.IsSupported, CKM.CKM_SHA3_384, CKM.CKM_SHA3_384_RSA_PKCS, CKM.CKM_SHA3_384_RSA_PKCS_PSS);
        AddIf(mechanisms, SHA3_512.IsSupported, CKM.CKM_SHA3_512, CKM.CKM_SHA3_512_RSA_PKCS, CKM.CKM_SHA3_512_RSA_PKCS_PSS);
        AddIf(mechanisms, HMACSHA3_256.IsSupported, CKM.CKM_SHA3_256_HMAC);
        AddIf(mechanisms, HMACSHA3_384.IsSupported, CKM.CKM_SHA3_384_HMAC);
        AddIf(mechanisms, HMACSHA3_512.IsSupported, CKM.CKM_SHA3_512_HMAC);
        AddIf(mechanisms, AesGcm.IsSupported, CKM.CKM_AES_GCM);
        AddIf(mechanisms, AesCcm.IsSupported, CKM.CKM_AES_CCM);
        AddIf(mechanisms, ChaCha20Poly1305.IsSupported, CKM.CKM_CHACHA20_POLY1305);
        AddIf(mechanisms, MLDsa.IsSupported, CKM.CKM_ML_DSA_KEY_PAIR_GEN, CKM.CKM_ML_DSA);
        AddIf(mechanisms, MLKem.IsSupported, CKM.CKM_ML_KEM_KEY_PAIR_GEN);
#pragma warning disable SYSLIB5006 // SlhDsa is evaluation-only; only its IsSupported is read.
        AddIf(mechanisms, SlhDsa.IsSupported, CKM.CKM_SLH_DSA_KEY_PAIR_GEN, CKM.CKM_SLH_DSA);
#pragma warning restore SYSLIB5006
        return mechanisms;
    }

    private static void AddIf(HashSet<CKM> mechanisms, bool hostSupports, params CKM[] added)
    {
        if (hostSupports)
            mechanisms.UnionWith(added);
    }

    public string LibraryPath => nameof(ManagedSoftToken);

    public Pkcs11Library Library { get; } = ManagedToken.NewLibrary();

    public NativeCULong SlotId => (NativeCULong)Library.GetSlotList().First().SlotId.Value;

    public ReadOnlyMemory<byte> SoPin { get; } = Encoding.UTF8.GetBytes("1234");

    public ReadOnlyMemory<byte> UserPin { get; } = Encoding.UTF8.GetBytes("1234");

    public string TokenLabel => ManagedSoftToken.TokenLabel;

    public IReadOnlySet<CKM> SupportedMechanisms => Implemented;

    public bool Supports(CKM mechanism) => Implemented.Contains(mechanism);

    public void Dispose() => Library.Dispose();
}
