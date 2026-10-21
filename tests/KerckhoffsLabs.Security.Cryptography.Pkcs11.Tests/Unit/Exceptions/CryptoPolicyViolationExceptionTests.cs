using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Exceptions;

/// <summary>
/// Covers both <see cref="CryptoPolicyViolationException"/> constructors: the policy-aware
/// constructor (carries <see cref="CryptoPolicyViolationException.PolicyName"/>,
/// <see cref="CryptoPolicyViolationException.Request"/>, <see cref="CryptoPolicyViolationException.Reason"/>
/// and <see cref="CryptoPolicyViolationException.Mechanism"/>), and the message-only overload used
/// for policy-independent refusals.
/// </summary>
#pragma warning disable KLPKCS11009, KLPKCS11010 // broken or deprecated mechanism and hash, used deliberately to build policy requests
public sealed class CryptoPolicyViolationExceptionTests
{
    [Fact]
    public void MessageCtor_SetsMessage_AndLeavesMechanismDefault()
    {
        const string message = "Refusing to export private key material from a non-extractable key.";
        var ex = new CryptoPolicyViolationException(message);

        Assert.Equal(message, ex.Message);
        Assert.Equal(default, ex.Mechanism);
    }

    [Fact]
    public void PolicyConstructor_CarriesPolicyRequestReasonAndMechanism()
    {
        var request = new MechanismUseRequest(new Mechanism(CKM.CKM_DES_ECB), CryptoOperation.Encrypt);

        var ex = new CryptoPolicyViolationException("SecureOnly", request, "DES is deprecated.");

        Assert.Equal("SecureOnly", ex.PolicyName);
        Assert.Same(request, ex.Request);
        Assert.Equal("DES is deprecated.", ex.Reason);
        Assert.Equal(CKM.CKM_DES_ECB, ex.Mechanism);
        Assert.Equal("SecureOnly policy refused CKM_DES_ECB for Encrypt: DES is deprecated.", ex.Message);
        Assert.IsType<System.Security.Cryptography.CryptographicException>(ex, exactMatch: false);
    }

    public static bool IsUnix => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    // CK_ULONG is 64-bit on Unix: a mechanism type wider than 32 bits is carried exactly and describes
    // itself as a vendor value while the denial is being reported.
    [Fact(SkipUnless = nameof(IsUnix), Skip = "Requires a 64-bit CK_ULONG")]
    public void PolicyConstructor_DescribesAMechanismWiderThan32Bits()
    {
        var request = new MechanismUseRequest(new Mechanism((CKM)0x1_0000_0001UL), CryptoOperation.Sign);

        var ex = new CryptoPolicyViolationException("SecureOnly", request, "Not reviewed.");

        Assert.Equal((CKM)0x1_0000_0001UL, ex.Mechanism);
        Assert.Equal("SecureOnly policy refused vendor mechanism 0x100000001 for Sign: Not reviewed.", ex.Message);
    }

    [Fact]
    public void PolicyConstructor_DescribesAVendorMechanismByItsHexValue()
    {
        var request = new MechanismUseRequest(new Mechanism((CKM)0x8000_1234UL), CryptoOperation.Sign);

        var ex = new CryptoPolicyViolationException("SecureOnly", request, "Not reviewed.");

        Assert.Equal((CKM)0x8000_1234U, ex.Mechanism);
        Assert.Equal("SecureOnly policy refused vendor mechanism 0x80001234 for Sign: Not reviewed.", ex.Message);
    }

    // Keyed by name so each theory row is serializable; the requests are built on demand.
    private static readonly Dictionary<string, (Func<PolicyRequest> Request, string Description)> DescribedRequests = new()
    {
        ["Hash"] = (() => new HashUseRequest(HashAlgorithmName.SHA1, CryptoOperation.Sign), "hash SHA1 for Sign"),
        ["RsaKeyGeneration"] = (() => new RsaKeyGenerationRequest(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, 1024), "RSA-1024 key generation (CKM_RSA_PKCS_KEY_PAIR_GEN)"),
        ["EcKeyGeneration"] = (() => new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.NistP256), $"EC key generation on {Pkcs11ECCurve.NamedCurves.NistP256}"),
        ["KeyTemplate"] = (() => new KeyTemplateRequest(null, []), "key template"),
        ["KeyTemplateWithClass"] = (() => new KeyTemplateRequest(CKO.CKO_SECRET_KEY, []), "key template (CKO_SECRET_KEY)"),
        ["KeyAgreementKdf"] = (() => new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_NULL), "CKM_ECDH1_DERIVE with CKD_NULL"),
        ["KeyAgreementKdfIntoDerivationOnlySecret"] = (
            () => new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_NULL) { ResultIsDerivationOnlySecret = true },
            "CKM_ECDH1_DERIVE with CKD_NULL into a derivation-only secret"),
        ["KeyAgreementKey"] = (() => new KeyAgreementKeyRequest(CKM.CKM_ECDH1_DERIVE, CKK.CKK_EC_MONTGOMERY), "CKM_ECDH1_DERIVE with a CKK_EC_MONTGOMERY key"),
        ["KeyMaterialExport"] = (() => new KeyMaterialExportRequest(KeyMaterialExportKind.KdfOutput), "export of KdfOutput"),
    };

    public static TheoryData<string> DescribedRequestKinds() => [.. DescribedRequests.Keys];

    // The description is what a caller (and the session's denial log line) sees of the refused request.
    [Theory]
    [MemberData(nameof(DescribedRequestKinds))]
    public void PolicyConstructor_DescribesEveryRequestKind(string kind)
    {
        (Func<PolicyRequest> request, string description) = DescribedRequests[kind];

        var ex = new CryptoPolicyViolationException("SecureOnly", request(), "Refused.");

        Assert.Equal($"SecureOnly policy refused {description}: Refused.", ex.Message);
    }

    // The template's attribute values (a key value here) must never reach the message or the log line.
    [Fact]
    public void PolicyConstructor_NeverDescribesKeyTemplateAttributeValues()
    {
        const string secret = "00112233445566778899AABBCCDDEEFF";
        var request = new KeyTemplateRequest(CKO.CKO_SECRET_KEY,
        [
            new ObjectAttribute(CKA.CKA_VALUE, Convert.FromHexString(secret)),
            new ObjectAttribute(CKA.CKA_LABEL, "label-" + secret),
        ]);

        var ex = new CryptoPolicyViolationException("SecureOnly", request, "Refused.");

        Assert.Equal("SecureOnly policy refused key template (CKO_SECRET_KEY): Refused.", ex.Message);
    }

    [Fact]
    public void PolicyConstructor_RejectsNullArguments()
    {
        var request = new MechanismUseRequest(new Mechanism(CKM.CKM_DES_ECB), CryptoOperation.Encrypt);

        Assert.Equal("policyName", Assert.Throws<ArgumentNullException>(
            () => new CryptoPolicyViolationException(null!, request, "reason")).ParamName);
        Assert.Equal("request", Assert.Throws<ArgumentNullException>(
            () => new CryptoPolicyViolationException("SecureOnly", null!, "reason")).ParamName);
        Assert.Equal("reason", Assert.Throws<ArgumentNullException>(
            () => new CryptoPolicyViolationException("SecureOnly", request, null!)).ParamName);
    }

    [Fact]
    public void MessageConstructor_LeavesPolicyFieldsNull()
    {
        var ex = new CryptoPolicyViolationException("Refusing to export.");
        Assert.Null(ex.PolicyName);
        Assert.Null(ex.Request);
        Assert.Null(ex.Mechanism);
    }
}
#pragma warning restore KLPKCS11009, KLPKCS11010
