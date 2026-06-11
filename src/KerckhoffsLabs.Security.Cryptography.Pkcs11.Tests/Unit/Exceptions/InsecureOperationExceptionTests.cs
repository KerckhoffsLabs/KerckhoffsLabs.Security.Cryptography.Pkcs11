using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Exceptions;

/// <summary>
/// Covers both <see cref="InsecureOperationException"/> constructors: the mechanism-based gate
/// (exposes <see cref="InsecureOperationException.Mechanism"/> and embeds the suggestion + the
/// AllowInsecure bypass hint) and the message-only overload used for operation-level refusals.
/// </summary>
public sealed class InsecureOperationExceptionTests
{
    [Fact]
    public void MechanismCtor_SetsMechanism_AndBuildsMessage()
    {
        var ex = new InsecureOperationException(CKM.CKM_RSA_PKCS, "Use CKM_RSA_PKCS_OAEP instead.");

        Assert.Equal(CKM.CKM_RSA_PKCS, ex.Mechanism);
        Assert.Contains(CKM.CKM_RSA_PKCS.ToString(), ex.Message);
        Assert.Contains("Use CKM_RSA_PKCS_OAEP instead.", ex.Message);
        Assert.Contains("AllowInsecure", ex.Message);
    }

    [Fact]
    public void MessageCtor_SetsMessage_AndLeavesMechanismDefault()
    {
        const string message = "Refusing to export private key material from a non-extractable key.";
        var ex = new InsecureOperationException(message);

        Assert.Equal(message, ex.Message);
        Assert.Equal(default, ex.Mechanism);
    }
}
