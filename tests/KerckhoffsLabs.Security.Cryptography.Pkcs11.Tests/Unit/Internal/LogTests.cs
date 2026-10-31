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
        Assert.Equal("Session(5): policy P allowed export of KdfOutput off the token", e.Message);
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
