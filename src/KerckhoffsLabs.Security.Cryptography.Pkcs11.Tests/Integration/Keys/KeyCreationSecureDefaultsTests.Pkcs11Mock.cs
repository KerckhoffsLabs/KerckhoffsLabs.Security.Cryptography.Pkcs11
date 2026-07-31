using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Every key-producing operation must apply the same secure-default gate as
/// <c>UnwrapKey</c> — reject an explicitly insecure result template (CKA_EXTRACTABLE=true or
/// CKA_SENSITIVE=false) unless AllowInsecure is set. This covers <c>DeriveKey</c> and the v3.2
/// <c>EncapsulateKey</c> / <c>DecapsulateKey</c> / <c>UnwrapKeyAuthenticated</c> paths. The gate
/// runs before the native call, so it is exercised on pkcs11-mock with dummy handles/blobs and a
/// secure (ungated) mechanism — no real key material needed.
/// </summary>
[Collection("Mock")]
public sealed class KeyCreationSecureDefaultsTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    // The four key-producing operations under test. Keyed by name so the [Theory] signature need not
    // expose the internal Pkcs11Session type. The gate fires before the native call; under
    // AllowInsecure the call proceeds to the mock, which fails the dummy/unsupported call with a
    // (non-insecure) Pkcs11Exception.
    // CA1825 false-positives on the xUnit TheoryData collection expression (not a zero-length array).
#pragma warning disable CA1825
    // Every session method that can create a token object belongs here. This list was previously
    // four entries, and the four it omitted — GenerateKey, GenerateKeyPair, CreateObject, CopyObject
    // — were precisely the four that did not run the gate. The list mirrored the gap rather than
    // catching it, so adding a creation path without adding it here is the failure mode to avoid.
    public static TheoryData<string> Operations() =>
        ["DeriveKey", "EncapsulateKey", "DecapsulateKey", "UnwrapKeyAuthenticated",
         "UnwrapKey", "GenerateKey", "GenerateKeyPair", "CreateObject", "CopyObject"];
#pragma warning restore CA1825

    private static void Invoke(string operation, Pkcs11Session s, List<ObjectAttribute> template)
    {
        switch (operation)
        {
            case "DeriveKey":
                {
                    var mech = new Mechanism(CKM.CKM_ECDH1_DERIVE);
                    s.DeriveKey(mech, new ObjectHandle(1UL), template);
                    break;
                }
            case "EncapsulateKey":
                {
                    var mech = new Mechanism(CKM.CKM_ML_KEM);
                    s.EncapsulateKey(mech, new ObjectHandle(1UL), template);
                    break;
                }
            case "DecapsulateKey":
                {
                    var mech = new Mechanism(CKM.CKM_ML_KEM);
                    s.DecapsulateKey(mech, new ObjectHandle(1UL), new byte[16], template);
                    break;
                }
            case "UnwrapKeyAuthenticated":
                {
                    var mech = new Mechanism(CKM.CKM_AES_GCM);
                    s.UnwrapKeyAuthenticated(mech, new ObjectHandle(1UL), new byte[16], [], template);
                    break;
                }
            case "UnwrapKey":
                {
                    var mech = new Mechanism(CKM.CKM_AES_KEY_WRAP_PAD);
                    s.UnwrapKey(mech, new ObjectHandle(1UL), new byte[24], template);
                    break;
                }
            case "GenerateKey":
                {
                    var mech = new Mechanism(CKM.CKM_AES_KEY_GEN);
                    s.GenerateKey(mech, template);
                    break;
                }
            case "GenerateKeyPair":
                {
                    var mech = new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN);
                    // The weakened attributes go on the private half; the public template is separate.
                    s.GenerateKeyPair(mech, [], template, out _, out _);
                    break;
                }
            case "CreateObject":
                s.CreateObject(template);
                break;
            case "CopyObject":
                s.CopyObject(new ObjectHandle(1UL), template);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(operation), operation, "Unknown operation.");
        }
    }

    // Opens a logged-in mock session, runs the body, and always closes it — leaking a session on
    // the shared Mock fixture would cascade into the other Mock-collection tests.
    private void WithSession(Action<Pkcs11Session> body)
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try { body(session); }
        finally { session.Logout(); session.CloseSession(); }
    }

    private static List<ObjectAttribute> SecretKeyTemplate(ObjectAttribute insecure) =>
    [
        new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
        new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET),
        insecure,
    ];

    /// <summary>
    /// <c>CKA_EXTRACTABLE=true</c> is permitted without opting in: an extractable key can be wrapped
    /// — exported encrypted under a KEK — which is the standard way to back up and transport keys,
    /// and PKCS#11 requires the attribute for it. Only <c>CKA_SENSITIVE=false</c>, which exposes the
    /// value in the clear, needs consent.
    /// </summary>
    [Theory]
    [MemberData(nameof(Operations))]
    public void ExplicitExtractableTrue_IsAllowed(string operation) => WithSession(session =>
    {
        var template = SecretKeyTemplate(new ObjectAttribute(CKA.CKA_EXTRACTABLE, true));
        try
        {
            Assert.IsNotType<InsecureOperationException>(
                Record.Exception(() => Invoke(operation, session, template)));
        }
        finally { foreach (var a in template) a.Dispose(); }
    });

    [Theory]
    [MemberData(nameof(Operations))]
    public void ExplicitSensitiveFalse_ThrowsByDefault(string operation) => WithSession(session =>
    {
        var template = SecretKeyTemplate(new ObjectAttribute(CKA.CKA_SENSITIVE, false));
        try
        {
            Assert.Throws<InsecureOperationException>(() => Invoke(operation, session, template));
        }
        finally { foreach (var a in template) a.Dispose(); }
    });

    [Theory]
    [MemberData(nameof(Operations))]
    public void InsecureTemplate_AllowInsecureScope_BypassesGate(string operation) => WithSession(session =>
    {
        var template = SecretKeyTemplate(new ObjectAttribute(CKA.CKA_EXTRACTABLE, true));
        try
        {
            using (session.AllowInsecureScope())
            {
                // The gate is bypassed; the call reaches the mock, which rejects the dummy/unsupported
                // call with a Pkcs11Exception — the point is it is NOT the insecure gate.
                Exception? ex = Record.Exception(() => Invoke(operation, session, template));
                Assert.False(ex is InsecureOperationException, "AllowInsecure should bypass the secure-default gate.");
            }
        }
        finally { foreach (var a in template) a.Dispose(); }
    });
}
