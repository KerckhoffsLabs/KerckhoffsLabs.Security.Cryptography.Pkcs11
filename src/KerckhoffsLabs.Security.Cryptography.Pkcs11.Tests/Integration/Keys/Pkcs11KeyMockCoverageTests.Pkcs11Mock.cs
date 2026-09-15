using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// pkcs11-mock's C_WrapKey/C_UnwrapKey only accept CKM_RSA_PKCS (no other mechanism reaches its
// sentinel-handle checks), and CKM_RSA_PKCS is also what's needed to reach Pkcs11Key.Encrypt/Decrypt's
// handle-selection logic without the call itself being the point under test — mechanism security is
// not what these tests pin, so the compile-time warning is suppressed for this file only.
#pragma warning disable KLPKCS11008

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Coverage for Pkcs11Key's handle-availability guards and mechanism-dispatch paths (Sign, Encrypt,
/// Decrypt, GetAttributeValue, MessageEncrypt/Decrypt, Wrap/Unwrap, Encapsulate/DecapsulateKey) that
/// the SoftHSM2/Kryoptic/opencryptoki/NSS-backed suites exercise but which don't run in this sandbox
/// (no loadable native module) — driven here against pkcs11-mock's fixed sentinel object handles
/// (CKA_CLASS-filtered, per vendor/pkcs11-mock/src/pkcs11-mock.c) instead. Message-based AEAD and
/// v3.2 encapsulate/decapsulate reach the native call and are then reported as
/// <see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> (stubbed / absent from the mock's function table,
/// respectively) rather than skipped — the point, as in <c>MessageApiTests.Pkcs11Mock.cs</c> and
/// <c>V32NotSupportedTests.Pkcs11Mock.cs</c>, is exercising the dispatch itself.
/// </summary>
[Collection("Mock")]
public sealed class Pkcs11KeyMockCoverageTests(MockBackendFixture backend)
{
    private readonly MockBackendFixture _backend = backend;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    private static ObjectHandle FindByClass(Pkcs11Workspace workspace, CKO objectClass)
    {
        using var findClass = new ObjectAttribute(CKA.CKA_CLASS, objectClass);
        return Assert.Single(workspace.Session.FindAllObjects([findClass]));
    }

    // === GetAttributeValue ==================================================

    [Fact]
    public void GetAttributeValue_SymmetricKeyPrivateHandleInvalid_Throws()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle publicSentinel = FindByClass(workspace, CKO.CKO_PUBLIC_KEY);

        // Deliberately mismatched: a symmetric key type always reads via the private handle, so a
        // key that only carries a "public" handle (however the caller obtained one) has no readable
        // handle at all from GetAttributeValue's point of view.
        using var key = new Pkcs11Key(
            workspace, privateHandle: ObjectHandle.Invalid, publicHandle: publicSentinel,
            keyType: CKK.CKK_AES, label: null, id: [], ownedLibrary: null, ownsWorkspace: false);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => key.GetAttributeValue(CKA.CKA_VALUE));
        Assert.Equal(CKR.CKR_OBJECT_HANDLE_INVALID, ex.ReturnValue);
    }

    // === Sign / Encrypt / Decrypt ===========================================

    [Fact]
    public void Sign_NoPrivateHandle_Throws()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle publicSentinel = FindByClass(workspace, CKO.CKO_PUBLIC_KEY);

        using var key = new Pkcs11Key(
            workspace, privateHandle: ObjectHandle.Invalid, publicHandle: publicSentinel,
            keyType: CKK.CKK_RSA, label: null, id: [], ownedLibrary: null, ownsWorkspace: false);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => key.Sign(new Mechanism(CKM.CKM_RSA_PKCS), "data"u8));
        Assert.Equal(CKR.CKR_OBJECT_HANDLE_INVALID, ex.ReturnValue);
    }

    [Fact]
    public void Encrypt_AsymmetricNoPublicHandle_Throws()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle privateSentinel = FindByClass(workspace, CKO.CKO_PRIVATE_KEY);

        using var key = new Pkcs11Key(
            workspace, privateHandle: privateSentinel, publicHandle: ObjectHandle.Invalid,
            keyType: CKK.CKK_RSA, label: null, id: [], ownedLibrary: null, ownsWorkspace: false);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => key.Encrypt(new Mechanism(CKM.CKM_RSA_PKCS), "data"u8));
        Assert.Equal(CKR.CKR_OBJECT_HANDLE_INVALID, ex.ReturnValue);
    }

    [Fact]
    public void Decrypt_NoPrivateHandle_Throws()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle publicSentinel = FindByClass(workspace, CKO.CKO_PUBLIC_KEY);

        using var key = new Pkcs11Key(
            workspace, privateHandle: ObjectHandle.Invalid, publicHandle: publicSentinel,
            keyType: CKK.CKK_RSA, label: null, id: [], ownedLibrary: null, ownsWorkspace: false);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => key.Decrypt(new Mechanism(CKM.CKM_RSA_PKCS), "data"u8));
        Assert.Equal(CKR.CKR_OBJECT_HANDLE_INVALID, ex.ReturnValue);
    }

    // === MessageEncrypt / MessageDecrypt ====================================

    [Fact]
    public void MessageEncrypt_AsymmetricNoPublicHandle_Throws()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle privateSentinel = FindByClass(workspace, CKO.CKO_PRIVATE_KEY);

        using var key = new Pkcs11Key(
            workspace, privateHandle: privateSentinel, publicHandle: ObjectHandle.Invalid,
            keyType: CKK.CKK_RSA, label: null, id: [], ownedLibrary: null, ownsWorkspace: false);

        var messageParams = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);
        var ex = Assert.ThrowsAny<Pkcs11Exception>(() =>
            key.MessageEncrypt(new Mechanism(CKM.CKM_AES_GCM), messageParams, [], "plaintext"u8.ToArray()));
        Assert.Equal(CKR.CKR_OBJECT_HANDLE_INVALID, ex.ReturnValue);
    }

    [Fact]
    public void MessageEncrypt_ValidHandle_ReportsFunctionNotSupported()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle secretSentinel = FindByClass(workspace, CKO.CKO_SECRET_KEY);

        using var key = new Pkcs11Key(
            workspace, privateHandle: secretSentinel, publicHandle: ObjectHandle.Invalid,
            keyType: CKK.CKK_AES, label: null, id: [], ownedLibrary: null, ownsWorkspace: false);

        using var scope = workspace.AllowInsecureScope();
        var messageParams = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);
        var ex = Assert.ThrowsAny<Pkcs11Exception>(() =>
            key.MessageEncrypt(new Mechanism(CKM.CKM_AES_GCM), messageParams, [], "plaintext"u8.ToArray()));
        Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
    }

    [Fact]
    public void MessageDecrypt_NoPrivateHandle_Throws()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle publicSentinel = FindByClass(workspace, CKO.CKO_PUBLIC_KEY);

        using var key = new Pkcs11Key(
            workspace, privateHandle: ObjectHandle.Invalid, publicHandle: publicSentinel,
            keyType: CKK.CKK_RSA, label: null, id: [], ownedLibrary: null, ownsWorkspace: false);

        var messageParams = CkmGcmMessageParams.ForDecrypt(new byte[12], new byte[16]);
        var ex = Assert.ThrowsAny<Pkcs11Exception>(() =>
            key.MessageDecrypt(new Mechanism(CKM.CKM_AES_GCM), messageParams, [], "ciphertext-ish"u8.ToArray()));
        Assert.Equal(CKR.CKR_OBJECT_HANDLE_INVALID, ex.ReturnValue);
    }

    [Fact]
    public void MessageDecrypt_ValidHandle_ReportsFunctionNotSupported()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle secretSentinel = FindByClass(workspace, CKO.CKO_SECRET_KEY);

        using var key = new Pkcs11Key(
            workspace, privateHandle: secretSentinel, publicHandle: ObjectHandle.Invalid,
            keyType: CKK.CKK_AES, label: null, id: [], ownedLibrary: null, ownsWorkspace: false);

        using var scope = workspace.AllowInsecureScope();
        var messageParams = CkmGcmMessageParams.ForDecrypt(new byte[12], new byte[16]);
        var ex = Assert.ThrowsAny<Pkcs11Exception>(() =>
            key.MessageDecrypt(new Mechanism(CKM.CKM_AES_GCM), messageParams, [], "ciphertext-ish"u8.ToArray()));
        Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
    }

    // === Wrap ================================================================
    //
    // pkcs11-mock's C_WrapKey requires exactly the PUBLIC_KEY sentinel as the wrapping handle and
    // the SECRET_KEY sentinel as the target, mechanism CKM_RSA_PKCS with no parameters — see
    // vendor/pkcs11-mock/src/pkcs11-mock.c. Unlike Unwrap/Derive/Encapsulate/DecapsulateKey, Wrap
    // returns raw bytes rather than hydrating a new Pkcs11Key, so its happy path needs nothing beyond
    // what the mock's C_GetAttributeValue already supports (which is limited to CKA_LABEL/CKA_VALUE).

    [Fact]
    public void Wrap_AsymmetricNoPublicHandle_Throws()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle privateSentinel = FindByClass(workspace, CKO.CKO_PRIVATE_KEY);
        ObjectHandle secretSentinel = FindByClass(workspace, CKO.CKO_SECRET_KEY);

        using var wrapper = new Pkcs11Key(
            workspace, privateHandle: privateSentinel, publicHandle: ObjectHandle.Invalid,
            keyType: CKK.CKK_RSA, label: null, id: [], ownedLibrary: null, ownsWorkspace: false);
        using var target = new Pkcs11Key(
            workspace, privateHandle: secretSentinel, publicHandle: ObjectHandle.Invalid,
            keyType: CKK.CKK_AES, label: null, id: [], ownedLibrary: null, ownsWorkspace: false);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(
            () => wrapper.Wrap(new Mechanism(CKM.CKM_RSA_PKCS), target));
        Assert.Equal(CKR.CKR_OBJECT_HANDLE_INVALID, ex.ReturnValue);
    }

    [Fact]
    public void Wrap_HappyPath_ReturnsWrappedBytes()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle publicSentinel = FindByClass(workspace, CKO.CKO_PUBLIC_KEY);
        ObjectHandle secretSentinel = FindByClass(workspace, CKO.CKO_SECRET_KEY);

        using var wrapper = new Pkcs11Key(
            workspace, privateHandle: ObjectHandle.Invalid, publicHandle: publicSentinel,
            keyType: CKK.CKK_RSA, label: null, id: [], ownedLibrary: null, ownsWorkspace: false);
        using var target = new Pkcs11Key(
            workspace, privateHandle: secretSentinel, publicHandle: ObjectHandle.Invalid,
            keyType: CKK.CKK_AES, label: null, id: [], ownedLibrary: null, ownsWorkspace: false);

        using var scope = workspace.AllowInsecureScope();
        byte[] wrapped = wrapper.Wrap(new Mechanism(CKM.CKM_RSA_PKCS), target);

        Assert.NotEmpty(wrapped);
    }

    // Unwrap's happy path is NOT covered here, unlike Wrap's: C_UnwrapKey succeeds against the mock
    // (returns the SECRET_KEY sentinel), but Pkcs11Key.Unwrap then calls
    // Pkcs11Workspace.HydrateExistingHandleAsKey on the result, which reads CKA_CLASS/CKA_KEY_TYPE —
    // attribute types pkcs11-mock's C_GetAttributeValue does not support at all (only CKA_LABEL and
    // CKA_VALUE; verified against vendor/pkcs11-mock/src/pkcs11-mock.c and empirically, where it
    // throws AttributeValueException). The same applies to EncapsulateKey/DecapsulateKey's result
    // hydration and Derive's, though those two are moot anyway since v3.2 is absent from the mock's
    // function table before hydration would ever be reached.

    // === EncapsulateKey / DecapsulateKey =====================================
    //
    // PKCS#11 v3.2 is entirely absent from pkcs11-mock's function table (verified against the vendor
    // source), so IsV32ApiSupported is false and the guard in LowLevelPkcs11Library fires before any
    // native call — the same CKR_FUNCTION_NOT_SUPPORTED outcome V32NotSupportedTests.Pkcs11Mock.cs
    // pins at the session level, exercised here through Pkcs11Key's own dispatch instead.

    [Fact]
    public void EncapsulateKey_NoPublicHandle_Throws()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle privateSentinel = FindByClass(workspace, CKO.CKO_PRIVATE_KEY);

        using var key = new Pkcs11Key(
            workspace, privateHandle: privateSentinel, publicHandle: ObjectHandle.Invalid,
            keyType: CKK.CKK_RSA, label: null, id: [], ownedLibrary: null, ownsWorkspace: false);

        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(32).Build();
        var ex = Assert.ThrowsAny<Pkcs11Exception>(
            () => key.EncapsulateKey(new Mechanism(CKM.CKM_ML_KEM), template));
        Assert.Equal(CKR.CKR_OBJECT_HANDLE_INVALID, ex.ReturnValue);
    }

    [Fact]
    public void EncapsulateKey_ValidHandle_ReportsFunctionNotSupported()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle publicSentinel = FindByClass(workspace, CKO.CKO_PUBLIC_KEY);

        using var key = new Pkcs11Key(
            workspace, privateHandle: ObjectHandle.Invalid, publicHandle: publicSentinel,
            keyType: CKK.CKK_ML_KEM, label: null, id: [], ownedLibrary: null, ownsWorkspace: false);

        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(32).Build();
        var ex = Assert.ThrowsAny<Pkcs11Exception>(
            () => key.EncapsulateKey(new Mechanism(CKM.CKM_ML_KEM), template, expectedCiphertextLen: 32));
        Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
    }

    [Fact]
    public void DecapsulateKey_NoPrivateHandle_Throws()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle publicSentinel = FindByClass(workspace, CKO.CKO_PUBLIC_KEY);

        using var key = new Pkcs11Key(
            workspace, privateHandle: ObjectHandle.Invalid, publicHandle: publicSentinel,
            keyType: CKK.CKK_ML_KEM, label: null, id: [], ownedLibrary: null, ownsWorkspace: false);

        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(32).Build();
        var ex = Assert.ThrowsAny<Pkcs11Exception>(
            () => key.DecapsulateKey(new Mechanism(CKM.CKM_ML_KEM), new byte[32], template));
        Assert.Equal(CKR.CKR_OBJECT_HANDLE_INVALID, ex.ReturnValue);
    }

    [Fact]
    public void DecapsulateKey_ValidHandle_ReportsFunctionNotSupported()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle privateSentinel = FindByClass(workspace, CKO.CKO_PRIVATE_KEY);

        using var key = new Pkcs11Key(
            workspace, privateHandle: privateSentinel, publicHandle: ObjectHandle.Invalid,
            keyType: CKK.CKK_ML_KEM, label: null, id: [], ownedLibrary: null, ownsWorkspace: false);

        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(32).Build();
        var ex = Assert.ThrowsAny<Pkcs11Exception>(
            () => key.DecapsulateKey(new Mechanism(CKM.CKM_ML_KEM), new byte[32], template));
        Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
    }

    // === Synthesized-parameter guards (internal, called directly) ===========

    [Fact]
    public void GetSynthesizedRsaParameters_NonRsaKeyType_ReturnsNull()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle privateSentinel = FindByClass(workspace, CKO.CKO_PRIVATE_KEY);

        using var key = new Pkcs11Key(
            workspace, privateHandle: privateSentinel, publicHandle: ObjectHandle.Invalid,
            keyType: CKK.CKK_AES, label: null, id: [], ownedLibrary: null, ownsWorkspace: false);

        Assert.Null(key.GetSynthesizedRsaParameters());
    }

    [Fact]
    public void GetSynthesizedRsaParameters_PublicHandlePresent_ReturnsNull()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle privateSentinel = FindByClass(workspace, CKO.CKO_PRIVATE_KEY);
        ObjectHandle publicSentinel = FindByClass(workspace, CKO.CKO_PUBLIC_KEY);

        using var key = new Pkcs11Key(
            workspace, privateHandle: privateSentinel, publicHandle: publicSentinel,
            keyType: CKK.CKK_RSA, label: null, id: [], ownedLibrary: null, ownsWorkspace: false);

        Assert.Null(key.GetSynthesizedRsaParameters());
    }

    [Fact]
    public void GetSynthesizedEcParameters_NonEcKeyType_ReturnsNull()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle privateSentinel = FindByClass(workspace, CKO.CKO_PRIVATE_KEY);

        using var key = new Pkcs11Key(
            workspace, privateHandle: privateSentinel, publicHandle: ObjectHandle.Invalid,
            keyType: CKK.CKK_RSA, label: null, id: [], ownedLibrary: null, ownsWorkspace: false);

        Assert.Null(key.GetSynthesizedEcParameters());
    }

    [Fact]
    public void GetSynthesizedEcParameters_PublicHandlePresent_ReturnsNull()
    {
        using var workspace = OpenWorkspace();
        ObjectHandle privateSentinel = FindByClass(workspace, CKO.CKO_PRIVATE_KEY);
        ObjectHandle publicSentinel = FindByClass(workspace, CKO.CKO_PUBLIC_KEY);

        using var key = new Pkcs11Key(
            workspace, privateHandle: privateSentinel, publicHandle: publicSentinel,
            keyType: CKK.CKK_EC, label: null, id: [], ownedLibrary: null, ownsWorkspace: false);

        Assert.Null(key.GetSynthesizedEcParameters());
    }
}
