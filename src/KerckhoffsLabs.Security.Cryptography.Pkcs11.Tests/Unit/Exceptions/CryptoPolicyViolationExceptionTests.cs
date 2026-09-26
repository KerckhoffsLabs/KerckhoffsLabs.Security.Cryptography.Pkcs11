using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Exceptions;

/// <summary>
/// Covers both <see cref="CryptoPolicyViolationException"/> constructors: the policy-aware
/// constructor (carries <see cref="CryptoPolicyViolationException.PolicyName"/>,
/// <see cref="CryptoPolicyViolationException.Request"/>, <see cref="CryptoPolicyViolationException.Reason"/>
/// and <see cref="CryptoPolicyViolationException.Mechanism"/>), and the message-only overload used
/// for policy-independent refusals.
/// </summary>
#pragma warning disable KLPKCS11009 // broken or deprecated mechanism, used deliberately to build a policy request
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
        Assert.IsAssignableFrom<System.Security.Cryptography.CryptographicException>(ex);
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
#pragma warning restore KLPKCS11009
