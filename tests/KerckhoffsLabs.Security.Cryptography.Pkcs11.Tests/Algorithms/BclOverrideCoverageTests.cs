using System.Reflection;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

// The legacy and evaluation-only adapters are named here only to inspect their types.
#pragma warning disable KLPKCS11001, KLPKCS11002, KLPKCS11003, KLPKCS11004, KLPKCS11005, KLPKCS11006, SYSLIB5006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Every member an adapter inherits from its BCL base classes, and does not override, runs the BCL's own
/// implementation against a token-backed key: the virtual members it leaves alone, the non-virtual ones
/// (most of the public surface, which validates and calls a protected Core) and the static ones, which
/// run in software even when called through the adapter's name. Each one listed here was read in the
/// .NET 10 source (dotnet/runtime, release/10.0) and is either <see cref="Reviewed"/>, with the reason the
/// base implementation is right for the adapter, or a <see cref="KnownGaps">known gap</see>, where it is not.
/// </summary>
/// <remarks>
/// The test fails when a .NET release adds a member, or an adapter stops overriding one, until the member
/// is reviewed here. It also fails on an entry no adapter inherits any more, so fixing a gap means removing
/// or moving its entry.
/// </remarks>
public sealed class BclOverrideCoverageTests
{
    internal static readonly Type[] AdapterTypes =
    [
        typeof(AesPkcs11), typeof(DESPkcs11), typeof(TripleDESPkcs11), typeof(RC2Pkcs11),
        typeof(RSAPkcs11), typeof(DSAPkcs11), typeof(ECDsaPkcs11), typeof(ECDiffieHellmanPkcs11),
        typeof(MLDsaPkcs11), typeof(MLKemPkcs11), typeof(SlhDsaPkcs11),
        typeof(HMACPkcs11), typeof(MD5Pkcs11), typeof(SHA1Pkcs11), typeof(SHA256Pkcs11), typeof(SHA384Pkcs11),
        typeof(SHA512Pkcs11), typeof(SHA3_256Pkcs11), typeof(SHA3_384Pkcs11), typeof(SHA3_512Pkcs11),
    ];

    public static TheoryData<Type> Adapters() => [.. AdapterTypes];

    // === Reasons a base implementation is right for the adapter ==============================

    private const string ImportRefused =
        "Ends in ImportParameters, which the adapter overrides to throw NotSupportedException: a token key is not replaced.";
    private const string PrivateExportRefused =
        "Ends in ExportParameters(true), which the adapter overrides to refuse with CryptoPolicyViolationException.";
    private const string PublicExport =
        "Ends in ExportParameters(false), which the adapter overrides to read the public key from the token.";
    private const string XmlThroughParameters =
        "Goes through ImportParameters and ExportParameters(includePrivateParameters), as the other key formats do.";
    private const string NoEcXmlFormat =
        "Throws NotImplementedException, as it does for the BCL's own implementations: EC keys have no XML format.";
    private const string NothingToRelease =
        "The adapter holds only the borrowed Pkcs11Key, which it does not dispose, so the base Dispose has nothing more to release.";
    private const string AlgorithmName =
        "A constant the algorithm's base class reports for every implementation.";
    private const string DsaHasNoAlgorithmName =
        "Throws NotImplementedException, as it does for DSA.Create(): no DSA base class defines a name.";
    private const string KeySizePinned =
        "Reads or validates against KeySizeValue and LegalKeySizesValue, which the constructor sets to the token key's single size: read from the token when it reports one, and fixed by the key type for Triple-DES.";
    private const string KeySizeFromToken =
        "Reads KeySizeValue, which the constructor sets from the token key's CKA_VALUE_LEN when the token reports it.";
    private const string Rc2EffectiveKeySize =
        "RC2's own validation against KeySize; the value is passed to the token in each operation's CK_RC2 parameters.";
    private const string NoRawKey =
        "Goes through the Key property, which throws NotSupportedException: the key is token-resident.";
    private const string FixedBlockSize =
        "The cipher's fixed block size, validated against LegalBlockSizes as for the BCL's own implementation.";
    private const string TransformSetting =
        "Configures only the ICryptoTransform, which the adapter does not offer; the one-shot methods take these as arguments.";
    private const string NoCfb =
        "Throws NotSupportedException: the adapter offers no CFB mode, as its remarks say.";
    private const string HashState =
        "State the base class keeps for every implementation: the hash size set at construction, the last hash, the block sizes.";
    private const string HashFinalCopied =
        "Copies the result of HashFinal, which the adapter overrides.";
    private const string RawRsaUnsupported =
        "Throws NotSupportedException, as for the BCL's own RSA implementations: the obsolete raw RSA operation.";
    private const string RsaEncryptCopied =
        "Copies the result of Encrypt or Decrypt, which the adapter overrides.";
    private const string EcdsaThroughSignHash =
        "Hashes through the HashData override, which applies the session's hash policy, and signs or verifies with SignHash or VerifyHash, which the adapter overrides; the formats are converted around them.";
    private const string DsaThroughCreateSignature =
        "Signs or verifies with CreateSignature or VerifySignature, which the adapter overrides; the formats are converted around them.";
    private const string DsaHashThroughOverride =
        "Hashes through the HashData override, which puts the hash to the session's policy.";
    private const string DsaVerifyThroughCore =
        "Ends in VerifySignatureCore, through the VerifyDataCore overrides where it hashes; the adapter overrides it to verify with CKM_DSA on the token, converting a DER signature to r‖s sized from CKA_SUBPRIME, so a token error propagates rather than reading as false.";
    private const string DsaMaxSignatureSizeNeedsPublicObject =
        "Reads q's length through ExportParameters(false), so it needs the public-key object for Y as that does, and throws Pkcs11Exception on a private-only key; not virtual, and documented in the adapter's remarks.";
    private const string RsaThroughSignHash =
        "Goes to SignHash or VerifyHash over byte arrays, which the adapter overrides; the base only copies around the call.";
    private const string RsaHashUnreached =
        "Reached only from the base class's SignData, TrySignData and VerifyData overloads, which the adapter overrides, so no RSAPkcs11 path hashes here.";
    private const string RsaModulusSize =
        "The modulus length in bytes, from KeySize, which the constructor sets from the token key's CKA_MODULUS_BITS or CKA_MODULUS.";
    private const string RsaStreamThroughVerifyHash =
        "Hashes through the HashData override, which puts the hash to the session's policy, and verifies with VerifyHash, which the adapter overrides.";
    private const string ForwardsToOverride =
        "Validates its arguments and forwards to the overload the adapter overrides.";
    private const string BlockThroughCore =
        "Checks the padding mode and IV size, then ends in the ECB or CBC TryEncrypt or TryDecrypt Core override, which runs the operation on the token under the session's policy and returns false with bytesWritten 0 when the result does not fit.";
    private const string CfbThroughCore =
        "Checks the padding mode, IV and feedback size, and the array-returning EncryptCfb the input length, then ends in the CFB Core, which AesPkcs11 overrides to refuse unpadded input that is not a whole number of feedback-size segments, with the BCL's CryptographicException, and run CKM_AES_CFB8 or CKM_AES_CFB128 on the token, and the other adapters inherit to throw NotSupportedException.";
    private const string KeyWrapThroughCore =
        "Checks the lengths and that the buffers do not overlap, then ends in EncryptKeyWrapPaddedCore or DecryptKeyWrapPaddedCore, which the adapter overrides to run on the token.";
    private const string LengthArithmetic =
        "Arithmetic over the block size, or the feedback size given, and the padding mode; it reads no key and calls no token.";
    private const string HashThroughCore =
        "Feeds the input to HashCore and finishes with HashFinal and Initialize, which the adapter overrides to compute the digest on the token.";
    private const string TryComputeHashSized =
        "Checks the destination against HashSizeValue, the digest size set at construction, then ends in HashCore and TryHashFinal as ComputeHash does.";
    private const string DisposeThroughOverride =
        "Calls Dispose(true), which the adapter overrides to release its input buffer.";
    private const string HmacHashName =
        "The hash name the constructor sets; setting another throws PlatformNotSupportedException, as for the BCL's own HMAC classes.";
    private const string ProtectedUnused =
        "Protected, and the adapter is sealed and never uses it, so no caller reaches it.";
    private const string ParameterSetFromToken =
        "Set once by the constructor from the token key's CKA_PARAMETER_SET, so every size the base class checks against is the token key's.";
    private const string DisposeMarksDisposed =
        "Calls Dispose(true), which has nothing to release because the adapter does not dispose the borrowed Pkcs11Key, and marks the instance disposed, so every later call throws ObjectDisposedException.";
    private const string PqSignThroughCore =
        "Checks the destination and signature sizes and the 255-byte context limit, then ends in SignDataCore or VerifyDataCore, which the adapter overrides to sign or verify on the token.";
    private const string PreHashUnsupported =
        "Checks the hash OID and length, then ends in SignPreHashCore or VerifyPreHashCore, which the adapter overrides to throw NotSupportedException: no PKCS#11 mechanism signs a caller's pre-hash.";
    private const string ExternalMuUnsupported =
        "Checks the mu and signature lengths, then ends in SignMuCore or VerifyMuCore, which the adapter overrides to throw NotSupportedException: PKCS#11 has no external-mu mechanism.";
    private const string PqPublicExport =
        "Ends in the public-key export Core, which the adapter overrides to read the public key's CKA_VALUE from the token, length-checked against the parameter set; the base only sizes or encodes it.";
    private const string PqPrivateExportRefused =
        "Ends in the private-key or seed export Core, which the adapter overrides to refuse with CryptoPolicyViolationException.";
    private const string Pkcs8ExportRefused =
        "Ends in TryExportPkcs8PrivateKeyCore, which the adapter overrides to refuse with CryptoPolicyViolationException; the encrypted forms check the PbeParameters first and encrypt nothing.";
    private const string Pkcs8TryExportRefused =
        "Returns false, exporting nothing, for a destination too small for any PKCS#8 key; otherwise ends in TryExportPkcs8PrivateKeyCore, which the adapter overrides to refuse with CryptoPolicyViolationException.";
    private const string KemThroughCore =
        "Checks the ciphertext and shared-secret sizes, then ends in EncapsulateCore or DecapsulateCore, which the adapter overrides to run on the token under the session's policy.";

    // A static member dispatches on no instance: called through an adapter's name (SHA256Pkcs11.HashData,
    // AesPkcs11.Create), it still runs the BCL's own implementation and never touches the token.
    private const string StaticFactory =
        "Static: creates the BCL's own implementation, never a token-backed adapter, even when called through the adapter's name.";
    private const string StaticHash =
        "Static: hashes in managed code, even when called through the adapter's name; an adapter instance hashes on the token.";
    private const string StaticSoftwareKey =
        "Static: creates a software key, even when called through the adapter's name; token keys are generated or found through Pkcs11Session.";
    private const string StaticPlatformSupport =
        "Static: reports the platform's support, not the token's, which Pkcs11Key.SupportsMechanism answers.";
    private const string StaticPureFunction =
        "Static: a function of its arguments alone, the same for every implementation.";

    internal static readonly Dictionary<string, string> Reviewed = new(StringComparer.Ordinal)
    {
        ["static Aes.Create()"] = StaticFactory,
        ["static Aes.Create(String)"] = StaticFactory,
        ["Aes.DecryptKeyWrapPadded(ReadOnlySpan<Byte>, Span<Byte>)"] = KeyWrapThroughCore,
        ["Aes.EncryptKeyWrapPadded(Byte[])"] = KeyWrapThroughCore,
        ["Aes.EncryptKeyWrapPadded(ReadOnlySpan<Byte>)"] = KeyWrapThroughCore,
        ["Aes.EncryptKeyWrapPadded(ReadOnlySpan<Byte>, Span<Byte>)"] = KeyWrapThroughCore,
        ["static Aes.GetKeyWrapPaddedLength(Int32)"] = StaticPureFunction,
        ["Aes.TryDecryptKeyWrapPadded(ReadOnlySpan<Byte>, Span<Byte>, out Int32)"] = KeyWrapThroughCore,
        ["AsymmetricAlgorithm.Clear()"] = NothingToRelease,
        ["static AsymmetricAlgorithm.Create()"] = StaticFactory,
        ["static AsymmetricAlgorithm.Create(String)"] = StaticFactory,
        ["AsymmetricAlgorithm.Dispose()"] = NothingToRelease,
        ["AsymmetricAlgorithm.Dispose(Boolean)"] = NothingToRelease,
        ["AsymmetricAlgorithm.ExportEncryptedPkcs8PrivateKey(ReadOnlySpan<Byte>, PbeParameters)"] = PrivateExportRefused,
        ["AsymmetricAlgorithm.ExportEncryptedPkcs8PrivateKey(ReadOnlySpan<Char>, PbeParameters)"] = PrivateExportRefused,
        ["AsymmetricAlgorithm.ExportEncryptedPkcs8PrivateKeyPem(ReadOnlySpan<Byte>, PbeParameters)"] = PrivateExportRefused,
        ["AsymmetricAlgorithm.ExportEncryptedPkcs8PrivateKeyPem(ReadOnlySpan<Char>, PbeParameters)"] = PrivateExportRefused,
        ["AsymmetricAlgorithm.ExportPkcs8PrivateKey()"] = PrivateExportRefused,
        ["AsymmetricAlgorithm.ExportPkcs8PrivateKeyPem()"] = PrivateExportRefused,
        ["AsymmetricAlgorithm.ExportSubjectPublicKeyInfo()"] = PublicExport,
        ["AsymmetricAlgorithm.ExportSubjectPublicKeyInfoPem()"] = PublicExport,
        ["AsymmetricAlgorithm.TryExportEncryptedPkcs8PrivateKeyPem(ReadOnlySpan<Byte>, PbeParameters, Span<Char>, out Int32)"] = PrivateExportRefused,
        ["AsymmetricAlgorithm.TryExportEncryptedPkcs8PrivateKeyPem(ReadOnlySpan<Char>, PbeParameters, Span<Char>, out Int32)"] = PrivateExportRefused,
        ["AsymmetricAlgorithm.TryExportPkcs8PrivateKeyPem(Span<Char>, out Int32)"] = PrivateExportRefused,
        ["AsymmetricAlgorithm.TryExportSubjectPublicKeyInfoPem(Span<Char>, out Int32)"] = PublicExport,
        ["AsymmetricAlgorithm.get_KeyExchangeAlgorithm()"] = DsaHasNoAlgorithmName,
        ["AsymmetricAlgorithm.get_KeySize()"] = KeySizePinned,
        ["AsymmetricAlgorithm.get_LegalKeySizes()"] = KeySizePinned,
        ["AsymmetricAlgorithm.get_SignatureAlgorithm()"] = DsaHasNoAlgorithmName,
        ["AsymmetricAlgorithm.set_KeySize(Int32)"] = KeySizePinned,
        ["static DES.Create()"] = StaticFactory,
        ["static DES.Create(String)"] = StaticFactory,
        ["static DES.IsSemiWeakKey(Byte[])"] = StaticPureFunction,
        ["static DES.IsWeakKey(Byte[])"] = StaticPureFunction,
        ["static DSA.Create()"] = StaticFactory,
        ["static DSA.Create(DSAParameters)"] = StaticFactory,
        ["static DSA.Create(Int32)"] = StaticFactory,
        ["static DSA.Create(String)"] = StaticFactory,
        ["DSA.CreateSignature(Byte[], DSASignatureFormat)"] = DsaThroughCreateSignature,
        ["DSA.CreateSignatureCore(ReadOnlySpan<Byte>, DSASignatureFormat)"] = DsaThroughCreateSignature,
        ["DSA.FromXmlString(String)"] = ImportRefused,
        ["DSA.GetMaxSignatureSize(DSASignatureFormat)"] = DsaMaxSignatureSizeNeedsPublicObject,
        ["DSA.ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, out Int32)"] = ImportRefused,
        ["DSA.ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<Char>, ReadOnlySpan<Byte>, out Int32)"] = ImportRefused,
        ["DSA.ImportFromEncryptedPem(ReadOnlySpan<Char>, ReadOnlySpan<Byte>)"] = ImportRefused,
        ["DSA.ImportFromEncryptedPem(ReadOnlySpan<Char>, ReadOnlySpan<Char>)"] = ImportRefused,
        ["DSA.ImportFromPem(ReadOnlySpan<Char>)"] = ImportRefused,
        ["DSA.ImportPkcs8PrivateKey(ReadOnlySpan<Byte>, out Int32)"] = ImportRefused,
        ["DSA.ImportSubjectPublicKeyInfo(ReadOnlySpan<Byte>, out Int32)"] = ImportRefused,
        ["DSA.SignData(Byte[], HashAlgorithmName)"] = DsaThroughCreateSignature,
        ["DSA.SignData(Byte[], HashAlgorithmName, DSASignatureFormat)"] = DsaThroughCreateSignature,
        ["DSA.SignData(Byte[], Int32, Int32, HashAlgorithmName)"] = DsaThroughCreateSignature,
        ["DSA.SignData(Byte[], Int32, Int32, HashAlgorithmName, DSASignatureFormat)"] = DsaThroughCreateSignature,
        ["DSA.SignData(Stream, HashAlgorithmName)"] = DsaThroughCreateSignature,
        ["DSA.SignData(Stream, HashAlgorithmName, DSASignatureFormat)"] = DsaThroughCreateSignature,
        ["DSA.SignDataCore(ReadOnlySpan<Byte>, HashAlgorithmName, DSASignatureFormat)"] = DsaThroughCreateSignature,
        ["DSA.SignDataCore(Stream, HashAlgorithmName, DSASignatureFormat)"] = DsaThroughCreateSignature,
        ["DSA.ToXmlString(Boolean)"] = XmlThroughParameters,
        ["DSA.TryCreateSignature(ReadOnlySpan<Byte>, Span<Byte>, DSASignatureFormat, out Int32)"] = DsaThroughCreateSignature,
        ["DSA.TryCreateSignature(ReadOnlySpan<Byte>, Span<Byte>, out Int32)"] = DsaThroughCreateSignature,
        ["DSA.TryCreateSignatureCore(ReadOnlySpan<Byte>, Span<Byte>, DSASignatureFormat, out Int32)"] = DsaThroughCreateSignature,
        ["DSA.TryExportEncryptedPkcs8PrivateKey(ReadOnlySpan<Byte>, PbeParameters, Span<Byte>, out Int32)"] = PrivateExportRefused,
        ["DSA.TryExportEncryptedPkcs8PrivateKey(ReadOnlySpan<Char>, PbeParameters, Span<Byte>, out Int32)"] = PrivateExportRefused,
        ["DSA.TryExportPkcs8PrivateKey(Span<Byte>, out Int32)"] = PrivateExportRefused,
        ["DSA.TryExportSubjectPublicKeyInfo(Span<Byte>, out Int32)"] = PublicExport,
        ["DSA.TryHashData(ReadOnlySpan<Byte>, Span<Byte>, HashAlgorithmName, out Int32)"] = DsaHashThroughOverride,
        ["DSA.TrySignData(ReadOnlySpan<Byte>, Span<Byte>, HashAlgorithmName, DSASignatureFormat, out Int32)"] = DsaThroughCreateSignature,
        ["DSA.TrySignDataCore(ReadOnlySpan<Byte>, Span<Byte>, HashAlgorithmName, DSASignatureFormat, out Int32)"] = DsaThroughCreateSignature,
        ["DSA.VerifyData(Byte[], Byte[], HashAlgorithmName)"] = ForwardsToOverride,
        ["DSA.VerifyData(Byte[], Byte[], HashAlgorithmName, DSASignatureFormat)"] = DsaVerifyThroughCore,
        ["DSA.VerifyData(Byte[], Int32, Int32, Byte[], HashAlgorithmName, DSASignatureFormat)"] = DsaVerifyThroughCore,
        ["DSA.VerifyData(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, HashAlgorithmName, DSASignatureFormat)"] = DsaVerifyThroughCore,
        ["DSA.VerifyData(Stream, Byte[], HashAlgorithmName, DSASignatureFormat)"] = DsaVerifyThroughCore,
        ["DSA.VerifySignature(Byte[], Byte[], DSASignatureFormat)"] = DsaVerifyThroughCore,
        ["DSA.VerifySignature(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>)"] = DsaThroughCreateSignature,
        ["DSA.VerifySignature(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, DSASignatureFormat)"] = DsaVerifyThroughCore,
        ["ECAlgorithm.ExportECPrivateKey()"] = PrivateExportRefused,
        ["ECAlgorithm.ExportECPrivateKeyPem()"] = PrivateExportRefused,
        ["ECAlgorithm.ImportECPrivateKey(ReadOnlySpan<Byte>, out Int32)"] = ImportRefused,
        ["ECAlgorithm.ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, out Int32)"] = ImportRefused,
        ["ECAlgorithm.ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<Char>, ReadOnlySpan<Byte>, out Int32)"] = ImportRefused,
        ["ECAlgorithm.ImportFromEncryptedPem(ReadOnlySpan<Char>, ReadOnlySpan<Byte>)"] = ImportRefused,
        ["ECAlgorithm.ImportFromEncryptedPem(ReadOnlySpan<Char>, ReadOnlySpan<Char>)"] = ImportRefused,
        ["ECAlgorithm.ImportFromPem(ReadOnlySpan<Char>)"] = ImportRefused,
        ["ECAlgorithm.ImportPkcs8PrivateKey(ReadOnlySpan<Byte>, out Int32)"] = ImportRefused,
        ["ECAlgorithm.ImportSubjectPublicKeyInfo(ReadOnlySpan<Byte>, out Int32)"] = ImportRefused,
        ["ECAlgorithm.TryExportECPrivateKey(Span<Byte>, out Int32)"] = PrivateExportRefused,
        ["ECAlgorithm.TryExportECPrivateKeyPem(Span<Char>, out Int32)"] = PrivateExportRefused,
        ["ECAlgorithm.TryExportEncryptedPkcs8PrivateKey(ReadOnlySpan<Byte>, PbeParameters, Span<Byte>, out Int32)"] = PrivateExportRefused,
        ["ECAlgorithm.TryExportEncryptedPkcs8PrivateKey(ReadOnlySpan<Char>, PbeParameters, Span<Byte>, out Int32)"] = PrivateExportRefused,
        ["ECAlgorithm.TryExportPkcs8PrivateKey(Span<Byte>, out Int32)"] = PrivateExportRefused,
        ["ECAlgorithm.TryExportSubjectPublicKeyInfo(Span<Byte>, out Int32)"] = PublicExport,
        ["static ECDiffieHellman.Create()"] = StaticFactory,
        ["static ECDiffieHellman.Create(ECCurve)"] = StaticFactory,
        ["static ECDiffieHellman.Create(ECParameters)"] = StaticFactory,
        ["static ECDiffieHellman.Create(String)"] = StaticFactory,
        ["ECDiffieHellman.DeriveKeyFromHash(ECDiffieHellmanPublicKey, HashAlgorithmName)"] = ForwardsToOverride,
        ["ECDiffieHellman.DeriveKeyFromHmac(ECDiffieHellmanPublicKey, HashAlgorithmName, Byte[])"] = ForwardsToOverride,
        ["ECDiffieHellman.FromXmlString(String)"] = NoEcXmlFormat,
        ["ECDiffieHellman.ToXmlString(Boolean)"] = NoEcXmlFormat,
        ["ECDiffieHellman.get_KeyExchangeAlgorithm()"] = AlgorithmName,
        ["ECDiffieHellman.get_SignatureAlgorithm()"] = AlgorithmName,
        ["static ECDsa.Create()"] = StaticFactory,
        ["static ECDsa.Create(ECCurve)"] = StaticFactory,
        ["static ECDsa.Create(ECParameters)"] = StaticFactory,
        ["static ECDsa.Create(String)"] = StaticFactory,
        ["ECDsa.FromXmlString(String)"] = NoEcXmlFormat,
        ["ECDsa.SignData(Byte[], HashAlgorithmName)"] = EcdsaThroughSignHash,
        ["ECDsa.SignData(Byte[], HashAlgorithmName, DSASignatureFormat)"] = EcdsaThroughSignHash,
        ["ECDsa.SignData(Byte[], Int32, Int32, HashAlgorithmName)"] = EcdsaThroughSignHash,
        ["ECDsa.SignData(Byte[], Int32, Int32, HashAlgorithmName, DSASignatureFormat)"] = EcdsaThroughSignHash,
        ["ECDsa.SignData(ReadOnlySpan<Byte>, HashAlgorithmName)"] = EcdsaThroughSignHash,
        ["ECDsa.SignData(ReadOnlySpan<Byte>, HashAlgorithmName, DSASignatureFormat)"] = EcdsaThroughSignHash,
        ["ECDsa.SignData(ReadOnlySpan<Byte>, Span<Byte>, HashAlgorithmName)"] = EcdsaThroughSignHash,
        ["ECDsa.SignData(ReadOnlySpan<Byte>, Span<Byte>, HashAlgorithmName, DSASignatureFormat)"] = EcdsaThroughSignHash,
        ["ECDsa.SignData(Stream, HashAlgorithmName, DSASignatureFormat)"] = EcdsaThroughSignHash,
        ["ECDsa.SignDataCore(ReadOnlySpan<Byte>, HashAlgorithmName, DSASignatureFormat)"] = EcdsaThroughSignHash,
        ["ECDsa.SignHash(Byte[], DSASignatureFormat)"] = EcdsaThroughSignHash,
        ["ECDsa.SignHash(ReadOnlySpan<Byte>)"] = EcdsaThroughSignHash,
        ["ECDsa.SignHash(ReadOnlySpan<Byte>, DSASignatureFormat)"] = EcdsaThroughSignHash,
        ["ECDsa.SignHash(ReadOnlySpan<Byte>, Span<Byte>)"] = EcdsaThroughSignHash,
        ["ECDsa.SignHash(ReadOnlySpan<Byte>, Span<Byte>, DSASignatureFormat)"] = EcdsaThroughSignHash,
        ["ECDsa.SignHashCore(ReadOnlySpan<Byte>, DSASignatureFormat)"] = EcdsaThroughSignHash,
        ["ECDsa.ToXmlString(Boolean)"] = NoEcXmlFormat,
        ["ECDsa.TryHashData(ReadOnlySpan<Byte>, Span<Byte>, HashAlgorithmName, out Int32)"] = EcdsaThroughSignHash,
        ["ECDsa.TrySignData(ReadOnlySpan<Byte>, Span<Byte>, HashAlgorithmName, DSASignatureFormat, out Int32)"] = EcdsaThroughSignHash,
        ["ECDsa.TrySignDataCore(ReadOnlySpan<Byte>, Span<Byte>, HashAlgorithmName, DSASignatureFormat, out Int32)"] = EcdsaThroughSignHash,
        ["ECDsa.TrySignHash(ReadOnlySpan<Byte>, Span<Byte>, DSASignatureFormat, out Int32)"] = EcdsaThroughSignHash,
        ["ECDsa.TrySignHash(ReadOnlySpan<Byte>, Span<Byte>, out Int32)"] = EcdsaThroughSignHash,
        ["ECDsa.TrySignHashCore(ReadOnlySpan<Byte>, Span<Byte>, DSASignatureFormat, out Int32)"] = EcdsaThroughSignHash,
        ["ECDsa.VerifyData(Byte[], Byte[], HashAlgorithmName)"] = ForwardsToOverride,
        ["ECDsa.VerifyData(Byte[], Byte[], HashAlgorithmName, DSASignatureFormat)"] = EcdsaThroughSignHash,
        ["ECDsa.VerifyData(Byte[], Int32, Int32, Byte[], HashAlgorithmName, DSASignatureFormat)"] = EcdsaThroughSignHash,
        ["ECDsa.VerifyData(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, HashAlgorithmName, DSASignatureFormat)"] = EcdsaThroughSignHash,
        ["ECDsa.VerifyData(Stream, Byte[], HashAlgorithmName)"] = EcdsaThroughSignHash,
        ["ECDsa.VerifyData(Stream, Byte[], HashAlgorithmName, DSASignatureFormat)"] = EcdsaThroughSignHash,
        ["ECDsa.VerifyHash(Byte[], Byte[], DSASignatureFormat)"] = EcdsaThroughSignHash,
        ["ECDsa.VerifyHash(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>)"] = EcdsaThroughSignHash,
        ["ECDsa.VerifyHash(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, DSASignatureFormat)"] = EcdsaThroughSignHash,
        ["ECDsa.get_KeyExchangeAlgorithm()"] = AlgorithmName,
        ["ECDsa.get_SignatureAlgorithm()"] = AlgorithmName,
        ["static HMAC.Create()"] = StaticFactory,
        ["static HMAC.Create(String)"] = StaticFactory,
        ["HMAC.get_BlockSizeValue()"] = ProtectedUnused,
        ["HMAC.get_HashName()"] = HmacHashName,
        ["HMAC.set_BlockSizeValue(Int32)"] = ProtectedUnused,
        ["HMAC.set_HashName(String)"] = HmacHashName,
        ["HashAlgorithm.Clear()"] = DisposeThroughOverride,
        ["HashAlgorithm.ComputeHash(Byte[])"] = HashThroughCore,
        ["HashAlgorithm.ComputeHash(Byte[], Int32, Int32)"] = HashThroughCore,
        ["HashAlgorithm.ComputeHash(Stream)"] = HashThroughCore,
        ["HashAlgorithm.ComputeHashAsync(Stream, CancellationToken)"] = HashThroughCore,
        ["static HashAlgorithm.Create()"] = StaticFactory,
        ["static HashAlgorithm.Create(String)"] = StaticFactory,
        ["HashAlgorithm.Dispose()"] = DisposeThroughOverride,
        ["HashAlgorithm.TransformBlock(Byte[], Int32, Int32, Byte[], Int32)"] = HashThroughCore,
        ["HashAlgorithm.TransformFinalBlock(Byte[], Int32, Int32)"] = HashThroughCore,
        ["HashAlgorithm.TryComputeHash(ReadOnlySpan<Byte>, Span<Byte>, out Int32)"] = TryComputeHashSized,
        ["HashAlgorithm.TryHashFinal(Span<Byte>, out Int32)"] = HashFinalCopied,
        ["HashAlgorithm.get_CanReuseTransform()"] = HashState,
        ["HashAlgorithm.get_CanTransformMultipleBlocks()"] = HashState,
        ["HashAlgorithm.get_Hash()"] = HashState,
        ["HashAlgorithm.get_HashSize()"] = HashState,
        ["HashAlgorithm.get_InputBlockSize()"] = HashState,
        ["HashAlgorithm.get_OutputBlockSize()"] = HashState,
        ["static KeyedHashAlgorithm.Create()"] = StaticFactory,
        ["static KeyedHashAlgorithm.Create(String)"] = StaticFactory,
        ["static MD5.Create()"] = StaticFactory,
        ["static MD5.Create(String)"] = StaticFactory,
        ["static MD5.HashData(Byte[])"] = StaticHash,
        ["static MD5.HashData(ReadOnlySpan<Byte>)"] = StaticHash,
        ["static MD5.HashData(ReadOnlySpan<Byte>, Span<Byte>)"] = StaticHash,
        ["static MD5.HashData(Stream)"] = StaticHash,
        ["static MD5.HashData(Stream, Span<Byte>)"] = StaticHash,
        ["static MD5.HashDataAsync(Stream, CancellationToken)"] = StaticHash,
        ["static MD5.HashDataAsync(Stream, Memory<Byte>, CancellationToken)"] = StaticHash,
        ["static MD5.TryHashData(ReadOnlySpan<Byte>, Span<Byte>, out Int32)"] = StaticHash,
        ["MLDsa.Dispose()"] = DisposeMarksDisposed,
        ["MLDsa.Dispose(Boolean)"] = NothingToRelease,
        ["MLDsa.ExportEncryptedPkcs8PrivateKey(ReadOnlySpan<Byte>, PbeParameters)"] = Pkcs8ExportRefused,
        ["MLDsa.ExportEncryptedPkcs8PrivateKey(ReadOnlySpan<Char>, PbeParameters)"] = Pkcs8ExportRefused,
        ["MLDsa.ExportEncryptedPkcs8PrivateKey(String, PbeParameters)"] = Pkcs8ExportRefused,
        ["MLDsa.ExportEncryptedPkcs8PrivateKeyPem(ReadOnlySpan<Byte>, PbeParameters)"] = Pkcs8ExportRefused,
        ["MLDsa.ExportEncryptedPkcs8PrivateKeyPem(ReadOnlySpan<Char>, PbeParameters)"] = Pkcs8ExportRefused,
        ["MLDsa.ExportEncryptedPkcs8PrivateKeyPem(String, PbeParameters)"] = Pkcs8ExportRefused,
        ["MLDsa.ExportMLDsaPrivateKey()"] = PqPrivateExportRefused,
        ["MLDsa.ExportMLDsaPrivateKey(Span<Byte>)"] = PqPrivateExportRefused,
        ["MLDsa.ExportMLDsaPrivateSeed()"] = PqPrivateExportRefused,
        ["MLDsa.ExportMLDsaPrivateSeed(Span<Byte>)"] = PqPrivateExportRefused,
        ["MLDsa.ExportMLDsaPublicKey()"] = PqPublicExport,
        ["MLDsa.ExportMLDsaPublicKey(Span<Byte>)"] = PqPublicExport,
        ["MLDsa.ExportPkcs8PrivateKey()"] = Pkcs8ExportRefused,
        ["MLDsa.ExportPkcs8PrivateKeyPem()"] = Pkcs8ExportRefused,
        ["MLDsa.ExportSubjectPublicKeyInfo()"] = PqPublicExport,
        ["MLDsa.ExportSubjectPublicKeyInfoPem()"] = PqPublicExport,
        ["static MLDsa.GenerateKey(MLDsaAlgorithm)"] = StaticSoftwareKey,
        ["static MLDsa.ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>)"] = StaticSoftwareKey,
        ["static MLDsa.ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<Char>, ReadOnlySpan<Byte>)"] = StaticSoftwareKey,
        ["static MLDsa.ImportEncryptedPkcs8PrivateKey(String, Byte[])"] = StaticSoftwareKey,
        ["static MLDsa.ImportFromEncryptedPem(ReadOnlySpan<Char>, ReadOnlySpan<Byte>)"] = StaticSoftwareKey,
        ["static MLDsa.ImportFromEncryptedPem(ReadOnlySpan<Char>, ReadOnlySpan<Char>)"] = StaticSoftwareKey,
        ["static MLDsa.ImportFromEncryptedPem(String, Byte[])"] = StaticSoftwareKey,
        ["static MLDsa.ImportFromEncryptedPem(String, String)"] = StaticSoftwareKey,
        ["static MLDsa.ImportFromPem(ReadOnlySpan<Char>)"] = StaticSoftwareKey,
        ["static MLDsa.ImportFromPem(String)"] = StaticSoftwareKey,
        ["static MLDsa.ImportMLDsaPrivateKey(MLDsaAlgorithm, Byte[])"] = StaticSoftwareKey,
        ["static MLDsa.ImportMLDsaPrivateKey(MLDsaAlgorithm, ReadOnlySpan<Byte>)"] = StaticSoftwareKey,
        ["static MLDsa.ImportMLDsaPrivateSeed(MLDsaAlgorithm, Byte[])"] = StaticSoftwareKey,
        ["static MLDsa.ImportMLDsaPrivateSeed(MLDsaAlgorithm, ReadOnlySpan<Byte>)"] = StaticSoftwareKey,
        ["static MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm, Byte[])"] = StaticSoftwareKey,
        ["static MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm, ReadOnlySpan<Byte>)"] = StaticSoftwareKey,
        ["static MLDsa.ImportPkcs8PrivateKey(Byte[])"] = StaticSoftwareKey,
        ["static MLDsa.ImportPkcs8PrivateKey(ReadOnlySpan<Byte>)"] = StaticSoftwareKey,
        ["static MLDsa.ImportSubjectPublicKeyInfo(Byte[])"] = StaticSoftwareKey,
        ["static MLDsa.ImportSubjectPublicKeyInfo(ReadOnlySpan<Byte>)"] = StaticSoftwareKey,
        ["MLDsa.SignData(Byte[], Byte[])"] = PqSignThroughCore,
        ["MLDsa.SignData(ReadOnlySpan<Byte>, Span<Byte>, ReadOnlySpan<Byte>)"] = PqSignThroughCore,
        ["MLDsa.SignMu(Byte[])"] = ExternalMuUnsupported,
        ["MLDsa.SignMu(ReadOnlySpan<Byte>)"] = ExternalMuUnsupported,
        ["MLDsa.SignMu(ReadOnlySpan<Byte>, Span<Byte>)"] = ExternalMuUnsupported,
        ["MLDsa.SignPreHash(Byte[], String, Byte[])"] = PreHashUnsupported,
        ["MLDsa.SignPreHash(ReadOnlySpan<Byte>, Span<Byte>, String, ReadOnlySpan<Byte>)"] = PreHashUnsupported,
        ["MLDsa.TryExportEncryptedPkcs8PrivateKey(ReadOnlySpan<Byte>, PbeParameters, Span<Byte>, out Int32)"] = Pkcs8ExportRefused,
        ["MLDsa.TryExportEncryptedPkcs8PrivateKey(ReadOnlySpan<Char>, PbeParameters, Span<Byte>, out Int32)"] = Pkcs8ExportRefused,
        ["MLDsa.TryExportEncryptedPkcs8PrivateKey(String, PbeParameters, Span<Byte>, out Int32)"] = Pkcs8ExportRefused,
        ["MLDsa.TryExportPkcs8PrivateKey(Span<Byte>, out Int32)"] = Pkcs8TryExportRefused,
        ["MLDsa.TryExportSubjectPublicKeyInfo(Span<Byte>, out Int32)"] = PqPublicExport,
        ["MLDsa.VerifyData(Byte[], Byte[], Byte[])"] = PqSignThroughCore,
        ["MLDsa.VerifyData(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, ReadOnlySpan<Byte>)"] = PqSignThroughCore,
        ["MLDsa.VerifyMu(Byte[], Byte[])"] = ExternalMuUnsupported,
        ["MLDsa.VerifyMu(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>)"] = ExternalMuUnsupported,
        ["MLDsa.VerifyPreHash(Byte[], Byte[], String, Byte[])"] = PreHashUnsupported,
        ["MLDsa.VerifyPreHash(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, String, ReadOnlySpan<Byte>)"] = PreHashUnsupported,
        ["MLDsa.get_Algorithm()"] = ParameterSetFromToken,
        ["static MLDsa.get_IsSupported()"] = StaticPlatformSupport,
        ["MLKem.Decapsulate(Byte[])"] = KemThroughCore,
        ["MLKem.Decapsulate(ReadOnlySpan<Byte>, Span<Byte>)"] = KemThroughCore,
        ["MLKem.Dispose()"] = DisposeMarksDisposed,
        ["MLKem.Dispose(Boolean)"] = NothingToRelease,
        ["MLKem.Encapsulate(Span<Byte>, Span<Byte>)"] = KemThroughCore,
        ["MLKem.Encapsulate(out Byte[], out Byte[])"] = KemThroughCore,
        ["MLKem.ExportDecapsulationKey()"] = PqPrivateExportRefused,
        ["MLKem.ExportDecapsulationKey(Span<Byte>)"] = PqPrivateExportRefused,
        ["MLKem.ExportEncapsulationKey()"] = PqPublicExport,
        ["MLKem.ExportEncapsulationKey(Span<Byte>)"] = PqPublicExport,
        ["MLKem.ExportEncryptedPkcs8PrivateKey(ReadOnlySpan<Byte>, PbeParameters)"] = Pkcs8ExportRefused,
        ["MLKem.ExportEncryptedPkcs8PrivateKey(ReadOnlySpan<Char>, PbeParameters)"] = Pkcs8ExportRefused,
        ["MLKem.ExportEncryptedPkcs8PrivateKey(String, PbeParameters)"] = Pkcs8ExportRefused,
        ["MLKem.ExportEncryptedPkcs8PrivateKeyPem(ReadOnlySpan<Byte>, PbeParameters)"] = Pkcs8ExportRefused,
        ["MLKem.ExportEncryptedPkcs8PrivateKeyPem(ReadOnlySpan<Char>, PbeParameters)"] = Pkcs8ExportRefused,
        ["MLKem.ExportEncryptedPkcs8PrivateKeyPem(String, PbeParameters)"] = Pkcs8ExportRefused,
        ["MLKem.ExportPkcs8PrivateKey()"] = Pkcs8ExportRefused,
        ["MLKem.ExportPkcs8PrivateKeyPem()"] = Pkcs8ExportRefused,
        ["MLKem.ExportPrivateSeed()"] = PqPrivateExportRefused,
        ["MLKem.ExportPrivateSeed(Span<Byte>)"] = PqPrivateExportRefused,
        ["MLKem.ExportSubjectPublicKeyInfo()"] = PqPublicExport,
        ["MLKem.ExportSubjectPublicKeyInfoPem()"] = PqPublicExport,
        ["static MLKem.GenerateKey(MLKemAlgorithm)"] = StaticSoftwareKey,
        ["static MLKem.ImportDecapsulationKey(MLKemAlgorithm, Byte[])"] = StaticSoftwareKey,
        ["static MLKem.ImportDecapsulationKey(MLKemAlgorithm, ReadOnlySpan<Byte>)"] = StaticSoftwareKey,
        ["static MLKem.ImportEncapsulationKey(MLKemAlgorithm, Byte[])"] = StaticSoftwareKey,
        ["static MLKem.ImportEncapsulationKey(MLKemAlgorithm, ReadOnlySpan<Byte>)"] = StaticSoftwareKey,
        ["static MLKem.ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>)"] = StaticSoftwareKey,
        ["static MLKem.ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<Char>, ReadOnlySpan<Byte>)"] = StaticSoftwareKey,
        ["static MLKem.ImportEncryptedPkcs8PrivateKey(String, Byte[])"] = StaticSoftwareKey,
        ["static MLKem.ImportFromEncryptedPem(ReadOnlySpan<Char>, ReadOnlySpan<Byte>)"] = StaticSoftwareKey,
        ["static MLKem.ImportFromEncryptedPem(ReadOnlySpan<Char>, ReadOnlySpan<Char>)"] = StaticSoftwareKey,
        ["static MLKem.ImportFromEncryptedPem(String, Byte[])"] = StaticSoftwareKey,
        ["static MLKem.ImportFromEncryptedPem(String, String)"] = StaticSoftwareKey,
        ["static MLKem.ImportFromPem(ReadOnlySpan<Char>)"] = StaticSoftwareKey,
        ["static MLKem.ImportFromPem(String)"] = StaticSoftwareKey,
        ["static MLKem.ImportPkcs8PrivateKey(Byte[])"] = StaticSoftwareKey,
        ["static MLKem.ImportPkcs8PrivateKey(ReadOnlySpan<Byte>)"] = StaticSoftwareKey,
        ["static MLKem.ImportPrivateSeed(MLKemAlgorithm, Byte[])"] = StaticSoftwareKey,
        ["static MLKem.ImportPrivateSeed(MLKemAlgorithm, ReadOnlySpan<Byte>)"] = StaticSoftwareKey,
        ["static MLKem.ImportSubjectPublicKeyInfo(Byte[])"] = StaticSoftwareKey,
        ["static MLKem.ImportSubjectPublicKeyInfo(ReadOnlySpan<Byte>)"] = StaticSoftwareKey,
        ["MLKem.TryExportEncryptedPkcs8PrivateKey(ReadOnlySpan<Byte>, PbeParameters, Span<Byte>, out Int32)"] = Pkcs8ExportRefused,
        ["MLKem.TryExportEncryptedPkcs8PrivateKey(ReadOnlySpan<Char>, PbeParameters, Span<Byte>, out Int32)"] = Pkcs8ExportRefused,
        ["MLKem.TryExportEncryptedPkcs8PrivateKey(String, PbeParameters, Span<Byte>, out Int32)"] = Pkcs8ExportRefused,
        ["MLKem.TryExportPkcs8PrivateKey(Span<Byte>, out Int32)"] = Pkcs8TryExportRefused,
        ["MLKem.TryExportSubjectPublicKeyInfo(Span<Byte>, out Int32)"] = PqPublicExport,
        ["MLKem.get_Algorithm()"] = ParameterSetFromToken,
        ["static MLKem.get_IsSupported()"] = StaticPlatformSupport,
        ["static RC2.Create()"] = StaticFactory,
        ["static RC2.Create(String)"] = StaticFactory,
        ["RC2.get_EffectiveKeySize()"] = Rc2EffectiveKeySize,
        ["RC2.get_KeySize()"] = KeySizeFromToken,
        ["RC2.set_EffectiveKeySize(Int32)"] = Rc2EffectiveKeySize,
        ["RC2.set_KeySize(Int32)"] = KeySizePinned,
        ["static RSA.Create()"] = StaticFactory,
        ["static RSA.Create(Int32)"] = StaticFactory,
        ["static RSA.Create(RSAParameters)"] = StaticFactory,
        ["static RSA.Create(String)"] = StaticFactory,
        ["RSA.Decrypt(ReadOnlySpan<Byte>, RSAEncryptionPadding)"] = RsaEncryptCopied,
        ["RSA.Decrypt(ReadOnlySpan<Byte>, Span<Byte>, RSAEncryptionPadding)"] = RsaEncryptCopied,
        ["RSA.DecryptValue(Byte[])"] = RawRsaUnsupported,
        ["RSA.Encrypt(ReadOnlySpan<Byte>, RSAEncryptionPadding)"] = RsaEncryptCopied,
        ["RSA.Encrypt(ReadOnlySpan<Byte>, Span<Byte>, RSAEncryptionPadding)"] = RsaEncryptCopied,
        ["RSA.EncryptValue(Byte[])"] = RawRsaUnsupported,
        ["RSA.ExportRSAPrivateKey()"] = PrivateExportRefused,
        ["RSA.ExportRSAPrivateKeyPem()"] = PrivateExportRefused,
        ["RSA.ExportRSAPublicKey()"] = PublicExport,
        ["RSA.ExportRSAPublicKeyPem()"] = PublicExport,
        ["RSA.FromXmlString(String)"] = ImportRefused,
        ["RSA.GetMaxOutputSize()"] = RsaModulusSize,
        ["RSA.HashData(Byte[], Int32, Int32, HashAlgorithmName)"] = RsaHashUnreached,
        ["RSA.ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, out Int32)"] = ImportRefused,
        ["RSA.ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<Char>, ReadOnlySpan<Byte>, out Int32)"] = ImportRefused,
        ["RSA.ImportFromEncryptedPem(ReadOnlySpan<Char>, ReadOnlySpan<Byte>)"] = ImportRefused,
        ["RSA.ImportFromEncryptedPem(ReadOnlySpan<Char>, ReadOnlySpan<Char>)"] = ImportRefused,
        ["RSA.ImportFromPem(ReadOnlySpan<Char>)"] = ImportRefused,
        ["RSA.ImportPkcs8PrivateKey(ReadOnlySpan<Byte>, out Int32)"] = ImportRefused,
        ["RSA.ImportRSAPrivateKey(ReadOnlySpan<Byte>, out Int32)"] = ImportRefused,
        ["RSA.ImportRSAPublicKey(ReadOnlySpan<Byte>, out Int32)"] = ImportRefused,
        ["RSA.ImportSubjectPublicKeyInfo(ReadOnlySpan<Byte>, out Int32)"] = ImportRefused,
        ["RSA.SignData(Byte[], HashAlgorithmName, RSASignaturePadding)"] = ForwardsToOverride,
        ["RSA.SignData(ReadOnlySpan<Byte>, HashAlgorithmName, RSASignaturePadding)"] = ForwardsToOverride,
        ["RSA.SignData(ReadOnlySpan<Byte>, Span<Byte>, HashAlgorithmName, RSASignaturePadding)"] = ForwardsToOverride,
        ["RSA.SignHash(ReadOnlySpan<Byte>, HashAlgorithmName, RSASignaturePadding)"] = RsaThroughSignHash,
        ["RSA.SignHash(ReadOnlySpan<Byte>, Span<Byte>, HashAlgorithmName, RSASignaturePadding)"] = RsaThroughSignHash,
        ["RSA.ToXmlString(Boolean)"] = XmlThroughParameters,
        ["RSA.TryDecrypt(ReadOnlySpan<Byte>, Span<Byte>, RSAEncryptionPadding, out Int32)"] = RsaEncryptCopied,
        ["RSA.TryEncrypt(ReadOnlySpan<Byte>, Span<Byte>, RSAEncryptionPadding, out Int32)"] = RsaEncryptCopied,
        ["RSA.TryExportEncryptedPkcs8PrivateKey(ReadOnlySpan<Byte>, PbeParameters, Span<Byte>, out Int32)"] = PrivateExportRefused,
        ["RSA.TryExportEncryptedPkcs8PrivateKey(ReadOnlySpan<Char>, PbeParameters, Span<Byte>, out Int32)"] = PrivateExportRefused,
        ["RSA.TryExportPkcs8PrivateKey(Span<Byte>, out Int32)"] = PrivateExportRefused,
        ["RSA.TryExportRSAPrivateKey(Span<Byte>, out Int32)"] = PrivateExportRefused,
        ["RSA.TryExportRSAPrivateKeyPem(Span<Char>, out Int32)"] = PrivateExportRefused,
        ["RSA.TryExportRSAPublicKey(Span<Byte>, out Int32)"] = PublicExport,
        ["RSA.TryExportRSAPublicKeyPem(Span<Char>, out Int32)"] = PublicExport,
        ["RSA.TryExportSubjectPublicKeyInfo(Span<Byte>, out Int32)"] = PublicExport,
        ["RSA.TryHashData(ReadOnlySpan<Byte>, Span<Byte>, HashAlgorithmName, out Int32)"] = RsaHashUnreached,
        ["RSA.TrySignHash(ReadOnlySpan<Byte>, Span<Byte>, HashAlgorithmName, RSASignaturePadding, out Int32)"] = RsaThroughSignHash,
        ["RSA.VerifyData(Byte[], Byte[], HashAlgorithmName, RSASignaturePadding)"] = ForwardsToOverride,
        ["RSA.VerifyData(Stream, Byte[], HashAlgorithmName, RSASignaturePadding)"] = RsaStreamThroughVerifyHash,
        ["RSA.VerifyHash(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, HashAlgorithmName, RSASignaturePadding)"] = RsaThroughSignHash,
        ["RSA.get_KeyExchangeAlgorithm()"] = AlgorithmName,
        ["RSA.get_SignatureAlgorithm()"] = AlgorithmName,
        ["static SHA1.Create()"] = StaticFactory,
        ["static SHA1.Create(String)"] = StaticFactory,
        ["static SHA1.HashData(Byte[])"] = StaticHash,
        ["static SHA1.HashData(ReadOnlySpan<Byte>)"] = StaticHash,
        ["static SHA1.HashData(ReadOnlySpan<Byte>, Span<Byte>)"] = StaticHash,
        ["static SHA1.HashData(Stream)"] = StaticHash,
        ["static SHA1.HashData(Stream, Span<Byte>)"] = StaticHash,
        ["static SHA1.HashDataAsync(Stream, CancellationToken)"] = StaticHash,
        ["static SHA1.HashDataAsync(Stream, Memory<Byte>, CancellationToken)"] = StaticHash,
        ["static SHA1.TryHashData(ReadOnlySpan<Byte>, Span<Byte>, out Int32)"] = StaticHash,
        ["static SHA256.Create()"] = StaticFactory,
        ["static SHA256.Create(String)"] = StaticFactory,
        ["static SHA256.HashData(Byte[])"] = StaticHash,
        ["static SHA256.HashData(ReadOnlySpan<Byte>)"] = StaticHash,
        ["static SHA256.HashData(ReadOnlySpan<Byte>, Span<Byte>)"] = StaticHash,
        ["static SHA256.HashData(Stream)"] = StaticHash,
        ["static SHA256.HashData(Stream, Span<Byte>)"] = StaticHash,
        ["static SHA256.HashDataAsync(Stream, CancellationToken)"] = StaticHash,
        ["static SHA256.HashDataAsync(Stream, Memory<Byte>, CancellationToken)"] = StaticHash,
        ["static SHA256.TryHashData(ReadOnlySpan<Byte>, Span<Byte>, out Int32)"] = StaticHash,
        ["static SHA384.Create()"] = StaticFactory,
        ["static SHA384.Create(String)"] = StaticFactory,
        ["static SHA384.HashData(Byte[])"] = StaticHash,
        ["static SHA384.HashData(ReadOnlySpan<Byte>)"] = StaticHash,
        ["static SHA384.HashData(ReadOnlySpan<Byte>, Span<Byte>)"] = StaticHash,
        ["static SHA384.HashData(Stream)"] = StaticHash,
        ["static SHA384.HashData(Stream, Span<Byte>)"] = StaticHash,
        ["static SHA384.HashDataAsync(Stream, CancellationToken)"] = StaticHash,
        ["static SHA384.HashDataAsync(Stream, Memory<Byte>, CancellationToken)"] = StaticHash,
        ["static SHA384.TryHashData(ReadOnlySpan<Byte>, Span<Byte>, out Int32)"] = StaticHash,
        ["static SHA3_256.Create()"] = StaticFactory,
        ["static SHA3_256.HashData(Byte[])"] = StaticHash,
        ["static SHA3_256.HashData(ReadOnlySpan<Byte>)"] = StaticHash,
        ["static SHA3_256.HashData(ReadOnlySpan<Byte>, Span<Byte>)"] = StaticHash,
        ["static SHA3_256.HashData(Stream)"] = StaticHash,
        ["static SHA3_256.HashData(Stream, Span<Byte>)"] = StaticHash,
        ["static SHA3_256.HashDataAsync(Stream, CancellationToken)"] = StaticHash,
        ["static SHA3_256.HashDataAsync(Stream, Memory<Byte>, CancellationToken)"] = StaticHash,
        ["static SHA3_256.TryHashData(ReadOnlySpan<Byte>, Span<Byte>, out Int32)"] = StaticHash,
        ["static SHA3_256.get_IsSupported()"] = StaticPlatformSupport,
        ["static SHA3_384.Create()"] = StaticFactory,
        ["static SHA3_384.HashData(Byte[])"] = StaticHash,
        ["static SHA3_384.HashData(ReadOnlySpan<Byte>)"] = StaticHash,
        ["static SHA3_384.HashData(ReadOnlySpan<Byte>, Span<Byte>)"] = StaticHash,
        ["static SHA3_384.HashData(Stream)"] = StaticHash,
        ["static SHA3_384.HashData(Stream, Span<Byte>)"] = StaticHash,
        ["static SHA3_384.HashDataAsync(Stream, CancellationToken)"] = StaticHash,
        ["static SHA3_384.HashDataAsync(Stream, Memory<Byte>, CancellationToken)"] = StaticHash,
        ["static SHA3_384.TryHashData(ReadOnlySpan<Byte>, Span<Byte>, out Int32)"] = StaticHash,
        ["static SHA3_384.get_IsSupported()"] = StaticPlatformSupport,
        ["static SHA3_512.Create()"] = StaticFactory,
        ["static SHA3_512.HashData(Byte[])"] = StaticHash,
        ["static SHA3_512.HashData(ReadOnlySpan<Byte>)"] = StaticHash,
        ["static SHA3_512.HashData(ReadOnlySpan<Byte>, Span<Byte>)"] = StaticHash,
        ["static SHA3_512.HashData(Stream)"] = StaticHash,
        ["static SHA3_512.HashData(Stream, Span<Byte>)"] = StaticHash,
        ["static SHA3_512.HashDataAsync(Stream, CancellationToken)"] = StaticHash,
        ["static SHA3_512.HashDataAsync(Stream, Memory<Byte>, CancellationToken)"] = StaticHash,
        ["static SHA3_512.TryHashData(ReadOnlySpan<Byte>, Span<Byte>, out Int32)"] = StaticHash,
        ["static SHA3_512.get_IsSupported()"] = StaticPlatformSupport,
        ["static SHA512.Create()"] = StaticFactory,
        ["static SHA512.Create(String)"] = StaticFactory,
        ["static SHA512.HashData(Byte[])"] = StaticHash,
        ["static SHA512.HashData(ReadOnlySpan<Byte>)"] = StaticHash,
        ["static SHA512.HashData(ReadOnlySpan<Byte>, Span<Byte>)"] = StaticHash,
        ["static SHA512.HashData(Stream)"] = StaticHash,
        ["static SHA512.HashData(Stream, Span<Byte>)"] = StaticHash,
        ["static SHA512.HashDataAsync(Stream, CancellationToken)"] = StaticHash,
        ["static SHA512.HashDataAsync(Stream, Memory<Byte>, CancellationToken)"] = StaticHash,
        ["static SHA512.TryHashData(ReadOnlySpan<Byte>, Span<Byte>, out Int32)"] = StaticHash,
        ["SlhDsa.Dispose()"] = DisposeMarksDisposed,
        ["SlhDsa.Dispose(Boolean)"] = NothingToRelease,
        ["SlhDsa.ExportEncryptedPkcs8PrivateKey(ReadOnlySpan<Byte>, PbeParameters)"] = Pkcs8ExportRefused,
        ["SlhDsa.ExportEncryptedPkcs8PrivateKey(ReadOnlySpan<Char>, PbeParameters)"] = Pkcs8ExportRefused,
        ["SlhDsa.ExportEncryptedPkcs8PrivateKey(String, PbeParameters)"] = Pkcs8ExportRefused,
        ["SlhDsa.ExportEncryptedPkcs8PrivateKeyPem(ReadOnlySpan<Byte>, PbeParameters)"] = Pkcs8ExportRefused,
        ["SlhDsa.ExportEncryptedPkcs8PrivateKeyPem(ReadOnlySpan<Char>, PbeParameters)"] = Pkcs8ExportRefused,
        ["SlhDsa.ExportEncryptedPkcs8PrivateKeyPem(String, PbeParameters)"] = Pkcs8ExportRefused,
        ["SlhDsa.ExportPkcs8PrivateKey()"] = Pkcs8ExportRefused,
        ["SlhDsa.ExportPkcs8PrivateKeyPem()"] = Pkcs8ExportRefused,
        ["SlhDsa.ExportSlhDsaPrivateKey()"] = PqPrivateExportRefused,
        ["SlhDsa.ExportSlhDsaPrivateKey(Span<Byte>)"] = PqPrivateExportRefused,
        ["SlhDsa.ExportSlhDsaPublicKey()"] = PqPublicExport,
        ["SlhDsa.ExportSlhDsaPublicKey(Span<Byte>)"] = PqPublicExport,
        ["SlhDsa.ExportSubjectPublicKeyInfo()"] = PqPublicExport,
        ["SlhDsa.ExportSubjectPublicKeyInfoPem()"] = PqPublicExport,
        ["static SlhDsa.GenerateKey(SlhDsaAlgorithm)"] = StaticSoftwareKey,
        ["static SlhDsa.ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>)"] = StaticSoftwareKey,
        ["static SlhDsa.ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<Char>, ReadOnlySpan<Byte>)"] = StaticSoftwareKey,
        ["static SlhDsa.ImportEncryptedPkcs8PrivateKey(String, Byte[])"] = StaticSoftwareKey,
        ["static SlhDsa.ImportFromEncryptedPem(ReadOnlySpan<Char>, ReadOnlySpan<Byte>)"] = StaticSoftwareKey,
        ["static SlhDsa.ImportFromEncryptedPem(ReadOnlySpan<Char>, ReadOnlySpan<Char>)"] = StaticSoftwareKey,
        ["static SlhDsa.ImportFromEncryptedPem(String, Byte[])"] = StaticSoftwareKey,
        ["static SlhDsa.ImportFromEncryptedPem(String, String)"] = StaticSoftwareKey,
        ["static SlhDsa.ImportFromPem(ReadOnlySpan<Char>)"] = StaticSoftwareKey,
        ["static SlhDsa.ImportFromPem(String)"] = StaticSoftwareKey,
        ["static SlhDsa.ImportPkcs8PrivateKey(Byte[])"] = StaticSoftwareKey,
        ["static SlhDsa.ImportPkcs8PrivateKey(ReadOnlySpan<Byte>)"] = StaticSoftwareKey,
        ["static SlhDsa.ImportSlhDsaPrivateKey(SlhDsaAlgorithm, Byte[])"] = StaticSoftwareKey,
        ["static SlhDsa.ImportSlhDsaPrivateKey(SlhDsaAlgorithm, ReadOnlySpan<Byte>)"] = StaticSoftwareKey,
        ["static SlhDsa.ImportSlhDsaPublicKey(SlhDsaAlgorithm, Byte[])"] = StaticSoftwareKey,
        ["static SlhDsa.ImportSlhDsaPublicKey(SlhDsaAlgorithm, ReadOnlySpan<Byte>)"] = StaticSoftwareKey,
        ["static SlhDsa.ImportSubjectPublicKeyInfo(Byte[])"] = StaticSoftwareKey,
        ["static SlhDsa.ImportSubjectPublicKeyInfo(ReadOnlySpan<Byte>)"] = StaticSoftwareKey,
        ["SlhDsa.SignData(Byte[], Byte[])"] = PqSignThroughCore,
        ["SlhDsa.SignData(ReadOnlySpan<Byte>, Span<Byte>, ReadOnlySpan<Byte>)"] = PqSignThroughCore,
        ["SlhDsa.SignPreHash(Byte[], String, Byte[])"] = PreHashUnsupported,
        ["SlhDsa.SignPreHash(ReadOnlySpan<Byte>, Span<Byte>, String, ReadOnlySpan<Byte>)"] = PreHashUnsupported,
        ["SlhDsa.TryExportEncryptedPkcs8PrivateKey(ReadOnlySpan<Byte>, PbeParameters, Span<Byte>, out Int32)"] = Pkcs8ExportRefused,
        ["SlhDsa.TryExportEncryptedPkcs8PrivateKey(ReadOnlySpan<Char>, PbeParameters, Span<Byte>, out Int32)"] = Pkcs8ExportRefused,
        ["SlhDsa.TryExportEncryptedPkcs8PrivateKey(String, PbeParameters, Span<Byte>, out Int32)"] = Pkcs8ExportRefused,
        ["SlhDsa.TryExportPkcs8PrivateKey(Span<Byte>, out Int32)"] = Pkcs8TryExportRefused,
        ["SlhDsa.TryExportSubjectPublicKeyInfo(Span<Byte>, out Int32)"] = PqPublicExport,
        ["SlhDsa.VerifyData(Byte[], Byte[], Byte[])"] = PqSignThroughCore,
        ["SlhDsa.VerifyData(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, ReadOnlySpan<Byte>)"] = PqSignThroughCore,
        ["SlhDsa.VerifyPreHash(Byte[], Byte[], String, Byte[])"] = PreHashUnsupported,
        ["SlhDsa.VerifyPreHash(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, String, ReadOnlySpan<Byte>)"] = PreHashUnsupported,
        ["SlhDsa.get_Algorithm()"] = ParameterSetFromToken,
        ["static SlhDsa.get_IsSupported()"] = StaticPlatformSupport,
        ["SymmetricAlgorithm.Clear()"] = NothingToRelease,
        ["static SymmetricAlgorithm.Create()"] = StaticFactory,
        ["static SymmetricAlgorithm.Create(String)"] = StaticFactory,
        ["SymmetricAlgorithm.CreateDecryptor()"] = NoRawKey,
        ["SymmetricAlgorithm.CreateEncryptor()"] = NoRawKey,
        ["SymmetricAlgorithm.DecryptCbc(Byte[], Byte[], PaddingMode)"] = BlockThroughCore,
        ["SymmetricAlgorithm.DecryptCbc(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, PaddingMode)"] = BlockThroughCore,
        ["SymmetricAlgorithm.DecryptCbc(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, PaddingMode)"] = BlockThroughCore,
        ["SymmetricAlgorithm.DecryptCfb(Byte[], Byte[], PaddingMode, Int32)"] = CfbThroughCore,
        ["SymmetricAlgorithm.DecryptCfb(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, PaddingMode, Int32)"] = CfbThroughCore,
        ["SymmetricAlgorithm.DecryptCfb(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, PaddingMode, Int32)"] = CfbThroughCore,
        ["SymmetricAlgorithm.DecryptEcb(Byte[], PaddingMode)"] = BlockThroughCore,
        ["SymmetricAlgorithm.DecryptEcb(ReadOnlySpan<Byte>, PaddingMode)"] = BlockThroughCore,
        ["SymmetricAlgorithm.DecryptEcb(ReadOnlySpan<Byte>, Span<Byte>, PaddingMode)"] = BlockThroughCore,
        ["SymmetricAlgorithm.Dispose()"] = NothingToRelease,
        ["SymmetricAlgorithm.Dispose(Boolean)"] = NothingToRelease,
        ["SymmetricAlgorithm.EncryptCbc(Byte[], Byte[], PaddingMode)"] = BlockThroughCore,
        ["SymmetricAlgorithm.EncryptCbc(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, PaddingMode)"] = BlockThroughCore,
        ["SymmetricAlgorithm.EncryptCbc(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, PaddingMode)"] = BlockThroughCore,
        ["SymmetricAlgorithm.EncryptCfb(Byte[], Byte[], PaddingMode, Int32)"] = CfbThroughCore,
        ["SymmetricAlgorithm.EncryptCfb(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, PaddingMode, Int32)"] = CfbThroughCore,
        ["SymmetricAlgorithm.EncryptCfb(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, PaddingMode, Int32)"] = CfbThroughCore,
        ["SymmetricAlgorithm.EncryptEcb(Byte[], PaddingMode)"] = BlockThroughCore,
        ["SymmetricAlgorithm.EncryptEcb(ReadOnlySpan<Byte>, PaddingMode)"] = BlockThroughCore,
        ["SymmetricAlgorithm.EncryptEcb(ReadOnlySpan<Byte>, Span<Byte>, PaddingMode)"] = BlockThroughCore,
        ["SymmetricAlgorithm.GetCiphertextLengthCbc(Int32, PaddingMode)"] = LengthArithmetic,
        ["SymmetricAlgorithm.GetCiphertextLengthCfb(Int32, PaddingMode, Int32)"] = LengthArithmetic,
        ["SymmetricAlgorithm.GetCiphertextLengthEcb(Int32, PaddingMode)"] = LengthArithmetic,
        ["SymmetricAlgorithm.SetKey(ReadOnlySpan<Byte>)"] = NoRawKey,
        ["SymmetricAlgorithm.SetKeyCore(ReadOnlySpan<Byte>)"] = NoRawKey,
        ["SymmetricAlgorithm.TryDecryptCbc(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, out Int32, PaddingMode)"] = BlockThroughCore,
        ["SymmetricAlgorithm.TryDecryptCfb(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, out Int32, PaddingMode, Int32)"] = CfbThroughCore,
        ["SymmetricAlgorithm.TryDecryptCfbCore(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, PaddingMode, Int32, out Int32)"] = NoCfb,
        ["SymmetricAlgorithm.TryDecryptEcb(ReadOnlySpan<Byte>, Span<Byte>, PaddingMode, out Int32)"] = BlockThroughCore,
        ["SymmetricAlgorithm.TryEncryptCbc(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, out Int32, PaddingMode)"] = BlockThroughCore,
        ["SymmetricAlgorithm.TryEncryptCfb(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, out Int32, PaddingMode, Int32)"] = CfbThroughCore,
        ["SymmetricAlgorithm.TryEncryptCfbCore(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, PaddingMode, Int32, out Int32)"] = NoCfb,
        ["SymmetricAlgorithm.TryEncryptEcb(ReadOnlySpan<Byte>, Span<Byte>, PaddingMode, out Int32)"] = BlockThroughCore,
        ["SymmetricAlgorithm.ValidKeySize(Int32)"] = KeySizePinned,
        ["SymmetricAlgorithm.get_BlockSize()"] = FixedBlockSize,
        ["SymmetricAlgorithm.get_FeedbackSize()"] = TransformSetting,
        ["SymmetricAlgorithm.get_IV()"] = TransformSetting,
        ["SymmetricAlgorithm.get_KeySize()"] = KeySizeFromToken,
        ["SymmetricAlgorithm.get_LegalBlockSizes()"] = FixedBlockSize,
        ["SymmetricAlgorithm.get_LegalKeySizes()"] = KeySizePinned,
        ["SymmetricAlgorithm.get_Mode()"] = TransformSetting,
        ["SymmetricAlgorithm.get_Padding()"] = TransformSetting,
        ["SymmetricAlgorithm.set_BlockSize(Int32)"] = FixedBlockSize,
        ["SymmetricAlgorithm.set_FeedbackSize(Int32)"] = TransformSetting,
        ["SymmetricAlgorithm.set_IV(Byte[])"] = TransformSetting,
        ["SymmetricAlgorithm.set_KeySize(Int32)"] = KeySizePinned,
        ["SymmetricAlgorithm.set_Mode(CipherMode)"] = TransformSetting,
        ["SymmetricAlgorithm.set_Padding(PaddingMode)"] = TransformSetting,
        ["static TripleDES.Create()"] = StaticFactory,
        ["static TripleDES.Create(String)"] = StaticFactory,
        ["static TripleDES.IsWeakKey(Byte[])"] = StaticPureFunction,
    };

    // === Known gaps: the base implementation is wrong for the adapter ========================

    // A member whose base implementation is wrong for its adapter is listed here with what goes wrong, until it
    // is fixed.
    private const string UnwrapLeftInPool =
        "Unwraps into a buffer rented from ArrayPool<byte>.Shared and returns it without zeroing it, so the unwrapped key stays in the shared pool; the BCL does this for every Aes and the method is not virtual. The overloads that write to the caller's destination leave nothing behind.";

    private const string EcdsaSignatureSizeFromField =
        "Sized from KeySize, the curve's field size, as the BCL sizes its own signatures. The token's r‖s takes the group order's length for r and s, so on secp160k1, secp160r1, secp160r2 and secp224k1, whose order is one bit longer than the field, the IEEE P1363 size is two bytes short; the DER size still fits. Not virtual, and documented in the adapter's remarks.";

    internal static readonly Dictionary<string, string> KnownGaps = new(StringComparer.Ordinal)
    {
        ["Aes.DecryptKeyWrapPadded(Byte[])"] = UnwrapLeftInPool,
        ["Aes.DecryptKeyWrapPadded(ReadOnlySpan<Byte>)"] = UnwrapLeftInPool,
        ["ECDsa.GetMaxSignatureSize(DSASignatureFormat)"] = EcdsaSignatureSizeFromField,
    };

    [Theory]
    [MemberData(nameof(Adapters))]
    public void EveryInheritedMember_IsReviewedOrAKnownGap(Type adapter)
    {
        string[] unreviewed = [.. Inherited(adapter).Where(m => !Reviewed.ContainsKey(m) && !KnownGaps.ContainsKey(m))];

        Assert.True(unreviewed.Length == 0,
            $"{adapter.Name} inherits, without overriding, members not reviewed here. Check each base " +
            $"implementation and override it or add it with a reason:\n{string.Join("\n", unreviewed)}");
    }

    [Fact]
    public void EveryEntry_IsStillInherited_ByAtLeastOneAdapter()
    {
        HashSet<string> inherited = [.. AdapterTypes.SelectMany(Inherited)];

        string[] inBoth = [.. Reviewed.Keys.Intersect(KnownGaps.Keys)];
        string[] stale = [.. Reviewed.Keys.Concat(KnownGaps.Keys).Where(m => !inherited.Contains(m))];

        Assert.Empty(inBoth);
        Assert.Empty(stale);
    }

    // A new adapter would otherwise go unchecked.
    [Fact]
    public void EveryAdapterOfABclType_IsListed()
    {
        Type[] adapters = [.. typeof(AesPkcs11).Assembly.GetExportedTypes()
            .Where(t => t.Namespace == typeof(AesPkcs11).Namespace && t.BaseType?.Namespace == "System.Security.Cryptography")];
        Type[] unlisted = [.. adapters.Except(AdapterTypes)];

        Assert.NotEmpty(adapters);
        Assert.Empty(unlisted);
    }

    private const BindingFlags AllMembers = BindingFlags.Instance | BindingFlags.Static | BindingFlags.FlattenHierarchy
        | BindingFlags.Public | BindingFlags.NonPublic;

    // The methods and accessors, instance or static, a caller or the adapter itself can reach (public,
    // protected or protected internal) that the adapter inherits from a BCL base class; object's own are
    // left out. GetMethods returns the most derived implementation of each, so an overridden member is
    // declared by the adapter itself.
    private static IEnumerable<string> Inherited(Type adapter) => adapter.GetMethods(AllMembers)
        .Where(m => m.DeclaringType != adapter && m.DeclaringType != typeof(object))
        .Where(m => m.IsPublic || m.IsFamily || m.IsFamilyOrAssembly)
        .Select(Signature);

    private static string Signature(MethodInfo m)
    {
        var sb = new StringBuilder(m.IsStatic ? "static " : "").Append(m.DeclaringType!.Name).Append('.').Append(m.Name).Append('(');
        sb.AppendJoin(", ", m.GetParameters().Select(p =>
            (p.IsOut ? "out " : p.ParameterType.IsByRef ? "ref " : "") + TypeName(p.ParameterType)));
        return sb.Append(')').ToString();
    }

    private static string TypeName(Type t)
    {
        if (t.IsByRef) return TypeName(t.GetElementType()!);
        if (t.IsArray) return TypeName(t.GetElementType()!) + "[]";
        if (!t.IsGenericType) return t.Name;
        string name = t.Name[..t.Name.IndexOf('`')];
        return $"{name}<{string.Join(", ", t.GetGenericArguments().Select(TypeName))}>";
    }
}
