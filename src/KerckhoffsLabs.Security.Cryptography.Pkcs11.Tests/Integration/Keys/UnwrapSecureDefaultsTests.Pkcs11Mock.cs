using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// UnwrapKey must reject an explicitly insecure result template (CKA_EXTRACTABLE=true or
/// CKA_SENSITIVE=false) unless AllowInsecure is set. The gate runs before the native C_UnwrapKey,
/// so it is exercised on pkcs11-mock with a dummy handle/blob and a secure (ungated) wrap mechanism
/// — no real key material needed.
/// </summary>
[Collection("Mock")]
public sealed class UnwrapSecureDefaultsTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    // Opens a logged-in mock session, runs the body, and always closes it — leaking a session on
    // the shared Mock fixture would cascade into the other Mock-collection tests.
    private void WithSession(Action<Pkcs11Session> body)
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try { body(session); }
        finally { session.Logout(); session.CloseSession(); }
    }

    private static List<ObjectAttribute> InsecureTemplate(ObjectAttribute insecure) =>
    [
        new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
        new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES),
        insecure,
    ];

    /// <summary>Unwrapping to an extractable key is permitted — see the note on wrapping in
    /// <c>KeyCreationSecureDefaultsTests.ExplicitExtractableTrue_IsAllowed</c>.</summary>
    [Fact]
    public void Unwrap_ExplicitExtractableTrue_IsAllowed() => WithSession(session =>
    {
        var mech = new Mechanism(CKM.CKM_AES_KEY_WRAP_PAD);
        var template = InsecureTemplate(new ObjectAttribute(CKA.CKA_EXTRACTABLE, true));
        try
        {
            Assert.IsNotType<InsecureOperationException>(Record.Exception(
                () => session.UnwrapKey(mech, new ObjectHandle(1UL), new byte[16], template)));
        }
        finally { foreach (var a in template) a.Dispose(); }
    });

    [Fact]
    public void Unwrap_ExplicitSensitiveFalse_ThrowsByDefault() => WithSession(session =>
    {
        var mech = new Mechanism(CKM.CKM_AES_KEY_WRAP_PAD);
        var template = InsecureTemplate(new ObjectAttribute(CKA.CKA_SENSITIVE, false));
        try
        {
            Assert.Throws<InsecureOperationException>(
                () => session.UnwrapKey(mech, new ObjectHandle(1UL), new byte[16], template));
        }
        finally { foreach (var a in template) a.Dispose(); }
    });

    [Fact]
    public void Unwrap_InsecureTemplate_AllowInsecureScope_BypassesGate() => WithSession(session =>
    {
        var mech = new Mechanism(CKM.CKM_AES_KEY_WRAP_PAD);
        var template = InsecureTemplate(new ObjectAttribute(CKA.CKA_EXTRACTABLE, true));
        try
        {
            using (session.AllowInsecureScope())
            {
                // The gate is bypassed; the call reaches the mock's C_UnwrapKey, which rejects the
                // non-RSA mechanism with a Pkcs11Exception — the point is it is NOT the insecure gate.
                Exception? ex = Record.Exception(
                    () => session.UnwrapKey(mech, new ObjectHandle(1UL), new byte[16], template));
                Assert.False(ex is InsecureOperationException, "AllowInsecure should bypass the unwrap secure-default gate.");
            }
        }
        finally { foreach (var a in template) a.Dispose(); }
    });
}
