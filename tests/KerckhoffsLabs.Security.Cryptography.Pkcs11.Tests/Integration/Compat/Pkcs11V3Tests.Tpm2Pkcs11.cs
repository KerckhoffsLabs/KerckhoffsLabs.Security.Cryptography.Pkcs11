using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Compat;

/// <summary>
/// tpm2-pkcs11's PKCS#11 v3.x interfaces, through the library: it reports v3.2, offers the v3.2, v3.1,
/// v3.0 and v2.40 interfaces, and implements the v3.0 and v3.2 functions a TPM token can (signature-first
/// verification, operation cancellation, validation flags); <c>C_LoginUser</c> takes no user name, as the
/// token has none.
/// </summary>
[Collection("Tpm2Pkcs11")]
public sealed class Pkcs11V3Tests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture backend)
{
    private readonly IPkcs11Backend _backend = backend;

    private static readonly byte[] Data = Encoding.UTF8.GetBytes("PKCS#11 v3.2 signature-first verification over a TPM key");

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void GetInfo_ReportsV32()
    {
        Assert.Equal(new Version(3, 2), _backend.Library.GetInfo().CryptokiVersion);
        Assert.True(_backend.Library.SupportsCryptokiVersion(new Version(3, 2)));
    }

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void GetInterfaces_OffersTheFourStandardInterfaces()
    {
        IReadOnlyList<InterfaceInfo> interfaces = _backend.Library.GetInterfaces();

        // v3.2, v3.1, v3.0 and v2.40; none fork safe, since a child can't use the parent's TPM connection.
        Assert.Equal(4, interfaces.Count);
        Assert.All(interfaces, i => Assert.Equal("PKCS 11", i.Name));
        Assert.All(interfaces, i => Assert.False(i.InterfaceFlags.ForkSafe));
    }

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable))]
    public void VerifySignature_OneShotAndStreamed_MatchTheSignature()
    {
        using var session = _backend.OpenSession();
        using Pkcs11Key key = session.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        var mechanism = new Mechanism(CKM.CKM_ECDSA_SHA256);
        byte[] signature = session.Core.Sign(mechanism, key.PrivateHandle, Data);

        Assert.True(session.Core.VerifySignature(mechanism, key.PublicHandle, signature, Data));

        byte[] tampered = [.. Data];
        tampered[0] ^= 0x01;
        Assert.False(session.Core.VerifySignature(mechanism, key.PublicHandle, signature, tampered));

        // C_VerifySignatureUpdate in 7-byte parts, then C_VerifySignatureFinal.
        using var stream = new MemoryStream(Data);
        Assert.True(session.Core.VerifySignature(mechanism, key.PublicHandle, signature, stream, bufferLength: 7));
    }

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void SessionCancel_EndsTheActiveOperation()
    {
        Pkcs11SessionCore session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            LowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
            var sid = (NativeCULong)session.SessionId;
            using var scope = new MechanismParameterScope();
            CK_MECHANISM sha256 = new Mechanism(CKM.CKM_SHA256).Marshal(scope, out _);

            Assert.Equal(CKR.CKR_OK, lowLevel.C_DigestInit(sid, in sha256));
            Assert.Equal(CKR.CKR_OPERATION_ACTIVE, lowLevel.C_DigestInit(sid, in sha256));

            session.CancelOperations((ulong)CKF.CKF_DIGEST);

            Assert.Equal(CKR.CKR_OK, lowLevel.C_DigestInit(sid, in sha256));
            session.CancelOperations((ulong)CKF.CKF_DIGEST);
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.Dispose();
        }
    }

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void SessionValidationFlags_AreNone()
    {
        using var session = _backend.OpenSession();
        Assert.Equal(0UL, session.Core.GetSessionValidationFlags(CksValidationFlagsType.CKS_LAST_VALIDATION_OK));
    }

    // The token has an SO and a user, but no user names: a name can't be checked against anything.
    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void LoginUser_WithAUserName_IsRefused()
    {
        using var session = _backend.OpenSession();
        var ex = Assert.ThrowsAny<Pkcs11Exception>(
            () => session.Core.LoginUser(CKU.CKU_USER, new SecurePin(_backend.UserPin.Span), "alice"));
        Assert.Equal(CKR.CKR_ARGUMENTS_BAD, ex.ReturnValue);
    }
}
