using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

// Verifies the source-generated [LoggerMessage] methods render the exact message text at the right
// level. Pass a CapturingLogger directly (the methods take ILogger), so no global state is touched.
public sealed class LogTests
{
    private static CapturingLogger.Entry Only(CapturingLogger log) => Assert.Single(log.Entries);

    [Fact]
    public void SessionTrace_RendersOperation()
    {
        var log = new CapturingLogger();
        Log.SessionTrace(log, 5, "Sign");
        var e = Only(log);
        Assert.Equal(LogLevel.Debug, e.Level);
        Assert.Equal("Session(5)::Sign", e.Message);
    }

    [Fact]
    public void LibraryTrace_RendersOperation()
    {
        var log = new CapturingLogger();
        Log.LibraryTrace(log, "lib.so", "GetInfo");
        var e = Only(log);
        Assert.Equal(LogLevel.Debug, e.Level);
        Assert.Equal("Pkcs11Library(lib.so)::GetInfo", e.Message);
    }

    [Fact]
    public void SlotTrace_RendersOperation()
    {
        var log = new CapturingLogger();
        Log.SlotTrace(log, 3, "OpenSessionCore");
        var e = Only(log);
        Assert.Equal(LogLevel.Debug, e.Level);
        Assert.Equal("Pkcs11Slot(3)::OpenSessionCore", e.Message);
    }

    [Fact]
    public void SessionCancelOperations_RendersHexFlags()
    {
        var log = new CapturingLogger();
        Log.SessionCancelOperations(log, 5, 0x1F);
        var e = Only(log);
        Assert.Equal(LogLevel.Debug, e.Level);
        Assert.Equal("Session(5)::CancelOperations flags=0x1F", e.Message);
    }

    [Fact]
    public void SessionGetValidationFlags_RendersHexType()
    {
        var log = new CapturingLogger();
        Log.SessionGetValidationFlags(log, 5, 0x2A);
        Assert.Equal("Session(5)::GetSessionValidationFlags type=0x2A", Only(log).Message);
    }

    [Fact]
    public void LoggingOutSession_IsInformation()
    {
        var log = new CapturingLogger();
        Log.LoggingOutSession(log, 7);
        Assert.Equal(LogLevel.Information, Only(log).Level);
        Assert.Equal("Logging out of session 7", Only(log).Message);
    }

    [Fact]
    public void LoadingLibrary_IsInformation()
    {
        var log = new CapturingLogger();
        Log.LoadingLibrary(log, "lib.so");
        var e = Only(log);
        Assert.Equal(LogLevel.Information, e.Level);
        Assert.Equal("Loading PKCS#11 library lib.so", e.Message);
    }

    [Fact]
    public void UnloadingLibrary_RendersPath()
    {
        var log = new CapturingLogger();
        Log.UnloadingLibrary(log, "lib.so");
        Assert.Equal("Unloading PKCS#11 library lib.so", Only(log).Message);
    }

    [Fact]
    public void UnloadingLibrary_NullPath_RendersNullToken()
    {
        var log = new CapturingLogger();
        Log.UnloadingLibrary(log, null);
        Assert.Equal("Unloading PKCS#11 library (null)", Only(log).Message);
    }

    [Fact]
    public void LoggingIn_IsInformation()
    {
        var log = new CapturingLogger();
        Log.LoggingIn(log, CKU.CKU_USER, 7);
        var e = Only(log);
        Assert.Equal(LogLevel.Information, e.Level);
        Assert.Equal("Logging as normal user into session 7", e.Message);
    }

    [Fact]
    public void LoggingInProtectedPath_IsInformation()
    {
        var log = new CapturingLogger();
        Log.LoggingInProtectedPath(log, CKU.CKU_SO, 7);
        var e = Only(log);
        Assert.Equal(LogLevel.Information, e.Level);
        Assert.Equal("Logging as security officer into session 7 via protected authentication path", e.Message);
    }

    [Fact]
    public void LoggingInUser_IsInformation()
    {
        var log = new CapturingLogger();
        Log.LoggingInUser(log, CKU.CKU_USER, 7);
        var e = Only(log);
        Assert.Equal(LogLevel.Information, e.Level);
        Assert.Equal("Logging in as normal user (username supplied) on session 7", e.Message);
    }

    [Fact]
    public void SessionOpened_IsInformation()
    {
        var log = new CapturingLogger();
        Log.SessionOpened(log, "read-write", 7, 1, "Recommended");
        var e = Only(log);
        Assert.Equal(LogLevel.Information, e.Level);
        Assert.Equal("Opened read-write session 7 with token in slot 1 under Recommended policy", e.Message);
    }

    [Fact]
    public void SessionCancelFailed_IsWarning()
    {
        var log = new CapturingLogger();
        Log.SessionCancelFailed(log, 7, "Encrypt", CKR.CKR_FUNCTION_FAILED);
        var e = Only(log);
        Assert.Equal(LogLevel.Warning, e.Level);
        Assert.Equal("Session(7)::Encrypt: C_SessionCancel returned CKR_FUNCTION_FAILED during cleanup", e.Message);
    }

    [Fact]
    public void FindObjectsFinalFailed_IsWarning()
    {
        var log = new CapturingLogger();
        Log.FindObjectsFinalFailed(log, 7, CKR.CKR_FUNCTION_FAILED);
        var e = Only(log);
        Assert.Equal(LogLevel.Warning, e.Level);
        Assert.Equal("Session(7)::FindAllObjects: C_FindObjectsFinal returned CKR_FUNCTION_FAILED", e.Message);
    }

    [Fact]
    public void MessageEncryptFinalFailed_IsWarning()
    {
        var log = new CapturingLogger();
        Log.MessageEncryptFinalFailed(log, CKR.CKR_FUNCTION_FAILED);
        Assert.Equal(LogLevel.Warning, Only(log).Level);
        Assert.Equal("C_MessageEncryptFinal returned CKR_FUNCTION_FAILED", Only(log).Message);
    }

    [Fact]
    public void MessageDecryptFinalFailed_IsWarning()
    {
        var log = new CapturingLogger();
        Log.MessageDecryptFinalFailed(log, CKR.CKR_FUNCTION_FAILED);
        Assert.Equal(LogLevel.Warning, Only(log).Level);
        Assert.Equal("C_MessageDecryptFinal returned CKR_FUNCTION_FAILED", Only(log).Message);
    }

    [Fact]
    public void OsLockingRefused_IsWarning()
    {
        var log = new CapturingLogger();
        Log.OsLockingRefused(log, "lib.so");
        var e = Only(log);
        Assert.Equal(LogLevel.Warning, e.Level);
        Assert.Equal("PKCS#11 library lib.so refused CKF_OS_LOCKING_OK; retrying without OS locking, and serializing every call into it", e.Message);
    }

    [Theory]
    [InlineData(CKU.CKU_SO, "security officer")]
    [InlineData(CKU.CKU_USER, "normal user")]
    [InlineData(CKU.CKU_CONTEXT_SPECIFIC, "context specific user")]
    public void UserTypeName_KnownUserTypes_MapToLabels(CKU userType, string expected)
        => Assert.Equal(expected, Log.UserTypeName(userType));

    [Fact]
    public void UserTypeName_UnknownUserType_FallsBackToEnumName()
    {
        var unknown = (CKU)99;
        Assert.Equal(unknown.ToString(), Log.UserTypeName(unknown));
    }

    [Fact]
    public void DisabledLevel_EmitsNothing()
    {
        var log = new CapturingLogger { Enabled = false };
        Log.SessionTrace(log, 5, "Sign");
        Log.LoggingOutSession(log, 5);
        Assert.Empty(log.Entries);
    }

    // === Key-material export warning ============================================================

    private static (Pkcs11Library Library, Pkcs11Session Session) OpenLogged(CapturingLogger log, ICryptoPolicy policy)
    {
        var library = new ManagedSoftToken().Load(new Pkcs11LibraryOptions { LoggerFactory = new CapturingLoggerFactory(log) });
        return (library, ManagedToken.OpenSession(library, policy));
    }

    private static Pkcs11Key ImportIkm(Pkcs11Session session)
    {
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Value(Convert.FromHexString("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")).Derive().Build();
        return session.ImportKey(tpl);
    }

    [Fact]
    public void KeyMaterialExportAllowed_RendersWarning()
    {
        var log = new CapturingLogger();
        Log.KeyMaterialExportAllowed(log, 5, "P", KeyMaterialExportKind.KdfOutput);
        var e = Only(log);
        Assert.Equal(LogLevel.Warning, e.Level);
        Assert.Equal("Session(5): policy P allowed export of KdfOutput off the token; further exports of KdfOutput under it log at Debug", e.Message);
    }

    [Fact]
    public void KeyMaterialExported_RendersDebug()
    {
        var log = new CapturingLogger();
        Log.KeyMaterialExported(log, 5, "P", KeyMaterialExportKind.KemSharedSecret);
        var e = Only(log);
        Assert.Equal(LogLevel.Debug, e.Level);
        Assert.Equal("Session(5): policy P allowed export of KemSharedSecret off the token", e.Message);
    }

    [Collection(FakeModuleCollection.Name)]
    public sealed class ExportLogging
    {
        [Fact]
        public void KeyMaterialExportAllowed_LogsWarningWithKindAndPolicy_NeverTheSecret()
        {
            var log = new CapturingLogger();
#pragma warning disable KLPKCS11012 // an allowed export is what the log line under test reports
            ICryptoPolicy policy = CryptoPolicy.Recommended.ToBuilder("Opt-in")
                .WithKeyMaterialExportRule(KeyMaterialExportRule.Allow([KeyMaterialExportKind.KdfOutput], "test")).Build();
#pragma warning restore KLPKCS11012
            var (library, session) = OpenLogged(log, policy);
            using (library)
            using (session)
            {
                using var ikm = ImportIkm(session);
                log.Clear();

                byte[] okm = HkdfPkcs11.DeriveKey(HashAlgorithmName.SHA256, ikm, 32, [1, 2, 3], [4, 5]);

                var warning = Assert.Single(log.Entries, e => e.Level == LogLevel.Warning);
                Assert.Contains("KdfOutput", warning.Message);
                Assert.Contains("Opt-in", warning.Message);
                string hex = Convert.ToHexString(okm);
                Assert.DoesNotContain(log.Entries, e => e.Message.Contains(hex, StringComparison.OrdinalIgnoreCase));
            }
        }

#pragma warning disable KLPKCS11012 // an allowed export is what the log lines under test report
        private static ICryptoPolicy OptIn(string name, params KeyMaterialExportKind[] kinds) =>
            CryptoPolicy.Recommended.ToBuilder(name)
                .WithKeyMaterialExportRule(KeyMaterialExportRule.Allow(kinds, "test")).Build();
#pragma warning restore KLPKCS11012

        private static int Exports(CapturingLogger log, LogLevel level) =>
            log.Entries.Count(e => e.Level == level && e.Message.Contains("allowed export"));

        // A hot KDF path warns once per policy and kind on the session, and logs every later export at Debug.
        [Fact]
        public void RepeatedExports_WarnOncePerPolicyAndKind_ThenLogAtDebug()
        {
            var log = new CapturingLogger();
            ICryptoPolicy first = OptIn("First", KeyMaterialExportKind.KdfOutput);
            var (library, session) = OpenLogged(log, first);
            using (library)
            using (session)
            {
                using var ikm = ImportIkm(session);
                log.Clear();

                for (int i = 0; i < 3; i++)
                    CryptographicOperations.ZeroMemory(HkdfPkcs11.DeriveKey(HashAlgorithmName.SHA256, ikm, 32, [1, 2, 3], [4, 5]));

                Assert.Equal(1, Exports(log, LogLevel.Warning));
                Assert.Equal(2, Exports(log, LogLevel.Debug));

                // Another policy is another decision to report: it warns once too.
                using (session.UsePolicy(OptIn("Second", KeyMaterialExportKind.KdfOutput)))
                {
                    log.Clear();
                    CryptographicOperations.ZeroMemory(HkdfPkcs11.DeriveKey(HashAlgorithmName.SHA256, ikm, 32, [1, 2, 3], [4, 5]));
                    CryptographicOperations.ZeroMemory(HkdfPkcs11.DeriveKey(HashAlgorithmName.SHA256, ikm, 32, [1, 2, 3], [4, 5]));
                    Assert.Contains("Second", Assert.Single(log.Entries, e => e.Level == LogLevel.Warning && e.Message.Contains("allowed export")).Message);
                    Assert.Equal(1, Exports(log, LogLevel.Debug));
                }

                // Back under the first policy: already reported on this session.
                log.Clear();
                CryptographicOperations.ZeroMemory(HkdfPkcs11.DeriveKey(HashAlgorithmName.SHA256, ikm, 32, [1, 2, 3], [4, 5]));
                Assert.Equal(0, Exports(log, LogLevel.Warning));
                Assert.Equal(1, Exports(log, LogLevel.Debug));
            }
        }

        // Allows everything but key agreement with an existing key, which it refuses.
        private sealed class RefusesKeyAgreementKeys : ICryptoPolicy
        {
            public string Name => "No agreement keys";
            public bool AllowsOverride => false;
            public PolicyDecision Evaluate(PolicyRequest request) =>
                request is KeyAgreementKeyRequest ? PolicyDecision.Deny("test") : PolicyDecision.Allow;
        }

        private static readonly byte[] X25519Oid = [0x06, 0x03, 0x2B, 0x65, 0x6E];
        private static readonly byte[] X25519Peer = Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        private static readonly byte[] X25519Shared = Convert.FromHexString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        private static byte[] X25519Spki(byte[] u)
        {
            var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
            using (writer.PushSequence())
            {
                using (writer.PushSequence())
                    writer.WriteObjectIdentifier("1.3.101.110");
                writer.WriteBitString(u);
            }
            return writer.Encode();
        }

        // The export check passes, but a later check, or the token, stops the read-back: nothing was exported,
        // so nothing is reported as exported.
        public static TheoryData<string> FailuresAfterTheExportCheck => ["refused key-agreement key", "token call fails", "wrong length"];

        [Theory]
        [MemberData(nameof(FailuresAfterTheExportCheck))]
        public void ReadBackThatFailsAfterTheExportCheck_LogsNoExport(string failure)
        {
            var log = new CapturingLogger();
            var module = new MontgomeryAgreementModule(
                X25519Oid,
                failure == "wrong length" ? X25519Shared[1..] : X25519Shared,
                failure == "token call fails" ? CKR.CKR_FUNCTION_FAILED : CKR.CKR_OK);
            ICryptoPolicy policy = failure == "refused key-agreement key"
                ? new RefusesKeyAgreementKeys()
                : OptIn("Opt-in", KeyMaterialExportKind.EcdhSharedSecret);
            using var key = module.CreateKey(policy, new CapturingLoggerFactory(log));

            Exception e = Assert.ThrowsAny<Exception>(() => key.Key.DeriveRawSecret(X25519Spki(X25519Peer)));

            Assert.IsType(failure switch
            {
                "refused key-agreement key" => typeof(CryptoPolicyViolationException),
                "token call fails" => typeof(Pkcs11Exception),
                _ => typeof(CryptographicException),
            }, e, exactMatch: false);
            Assert.Equal(0, Exports(log, LogLevel.Warning) + Exports(log, LogLevel.Debug));
        }

        [Fact]
        public void SuccessfulRawSecretReadBack_LogsTheExport()
        {
            var log = new CapturingLogger();
            var module = new MontgomeryAgreementModule(X25519Oid, X25519Shared);
            using var key = module.CreateKey(OptIn("Opt-in", KeyMaterialExportKind.EcdhSharedSecret), new CapturingLoggerFactory(log));

            byte[] z = key.Key.DeriveRawSecret(X25519Spki(X25519Peer));

            var warning = Assert.Single(log.Entries, e => e.Level == LogLevel.Warning);
            Assert.Contains("EcdhSharedSecret", warning.Message);
            Assert.DoesNotContain(log.Entries, e => e.Message.Contains(Convert.ToHexString(z), StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public void RefusedExport_LogsPolicyDenied_NotKeyMaterialExportAllowed()
        {
            var log = new CapturingLogger();
            var (library, session) = OpenLogged(log, CryptoPolicy.Recommended);
            using (library)
            using (session)
            {
                using var ikm = ImportIkm(session);
                log.Clear();

                Assert.Throws<CryptoPolicyViolationException>(
                    () => HkdfPkcs11.DeriveKey(HashAlgorithmName.SHA256, ikm, 32, [1, 2, 3], [4, 5]));

                Assert.Contains(log.Entries, e => e.Message.Contains("refused"));
                Assert.DoesNotContain(log.Entries, e => e.Message.Contains("allowed export"));
            }
        }
    }
}
