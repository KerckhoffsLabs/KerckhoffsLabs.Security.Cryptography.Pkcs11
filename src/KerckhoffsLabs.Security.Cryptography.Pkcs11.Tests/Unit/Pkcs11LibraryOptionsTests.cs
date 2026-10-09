using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// <see cref="Pkcs11LibraryOptions.ModuleParameters"/>: what a module receives in
/// <c>CK_C_INITIALIZE_ARGS.pReserved</c>, including on the <c>CKR_CANT_LOCK</c> retry, and the inputs
/// refused before any call reaches the module. NSS softoken before 3.52 is the motivating module: it
/// returns <c>CKR_ARGUMENTS_BAD</c> without its parameter string.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11LibraryOptionsTests
{
    private const string NssParameters =
        "configdir='' certPrefix='' keyPrefix='' secmod='' flags=readOnly,noCertDB,noModDB,forceOpen";

    [Fact]
    public void ModuleParameters_ArePassedInPReserved_AsNulTerminatedUtf8()
    {
        // Non-ASCII, so a narrowing or ANSI conversion would show.
        const string parameters = NssParameters + " tokenDescription='Jeton crypté'";
        using var module = new ParametersModule();

        using (module.Load(new Pkcs11LibraryOptions { ModuleParameters = parameters }))
        {
            var call = Assert.Single(module.Received);
            Assert.Equal(CKF.CKF_OS_LOCKING_OK, call.Flags);
            Assert.Equal(parameters, call.Reserved);
        }
    }

    [Fact]
    public void WithoutModuleParameters_PReservedIsNull()
    {
        using var module = new ParametersModule();

        using (module.Load(new Pkcs11LibraryOptions()))
            Assert.Null(Assert.Single(module.Received).Reserved);
    }

    /// <summary>
    /// The no-locking retry must keep the parameters: a module that needs them would refuse a bare
    /// <c>NULL</c>. No flags and no mutex callbacks is the standard's single-threaded declaration, so
    /// the library still serializes every call into the module.
    /// </summary>
    [Fact]
    public void ModuleThatCannotLock_IsRetriedWithTheParametersAndNoFlags_AndSerialized()
    {
        using var module = new ParametersModule { CannotLock = true };

        using var library = module.Load(new Pkcs11LibraryOptions { ModuleParameters = NssParameters });

        Assert.Equal(2, module.Received.Count);
        Assert.Equal(CKF.CKF_OS_LOCKING_OK, module.Received[0].Flags);
        Assert.NotNull(module.Received[1].Args);
        Assert.Equal(0UL, module.Received[1].Flags);
        Assert.Equal(NssParameters, module.Received[1].Reserved);
        Assert.False(library.SupportsConcurrentAccess);
    }

    /// <summary>The motivating case: a module that refuses to initialize without its parameters.</summary>
    [Fact]
    public void ModuleRequiringParameters_InitializesOnlyWhenGivenThem()
    {
        using (var without = new ParametersModule { RequireParameters = true })
            Assert.Equal(CKR.CKR_ARGUMENTS_BAD,
                Assert.ThrowsAny<Pkcs11Exception>(() => without.Load()).ReturnValue);

        using var with = new ParametersModule { RequireParameters = true };
        using var library = with.Load(new Pkcs11LibraryOptions { ModuleParameters = NssParameters });
        Assert.True(library.SupportsConcurrentAccess);
    }

    [Fact]
    public void ModuleParameters_WithANulCharacter_AreRefused()
    {
        var ex = Assert.Throws<ArgumentException>(() => new Pkcs11LibraryOptions { ModuleParameters = "flags=readOnly\0noCertDB" });
        Assert.Equal(nameof(Pkcs11LibraryOptions.ModuleParameters), ex.ParamName);
    }

    [Fact]
    public void ModuleParameters_ThatAreNotValidUtf16_AreRefused_BeforeReachingTheModule()
    {
        using var module = new ParametersModule();

        var ex = Assert.Throws<ArgumentException>(() => module.Load(new Pkcs11LibraryOptions { ModuleParameters = "flags=\uD800" }));

        Assert.Equal(nameof(Pkcs11LibraryOptions.ModuleParameters), ex.ParamName);
        Assert.Empty(module.Received);
    }

    /// <summary>Some modules take credentials in their parameter string, so it never reaches a log —
    /// including the warning the no-locking retry emits.</summary>
    [Fact]
    public void ModuleParameters_AreNeverLogged()
    {
        const string parameters = "configdir='/secret/path' password=hunter2";
        var logger = new CapturingLogger();
        using var module = new ParametersModule { CannotLock = true };

        using (module.Load(new Pkcs11LibraryOptions { ModuleParameters = parameters, LoggerFactory = new CapturingLoggerFactory(logger) }))
        {
            Assert.NotEmpty(logger.Entries);
            Assert.DoesNotContain(logger.Entries, e => e.Message.Contains("hunter2", StringComparison.Ordinal)
                || e.Message.Contains("/secret/path", StringComparison.Ordinal));
        }
    }

    [Fact]
    public void Load_RejectsNullOptions()
        => Assert.Equal("options",
            Assert.Throws<ArgumentNullException>(() => Pkcs11Library.Load("unused", (Pkcs11LibraryOptions)null!)).ParamName);

    private sealed class ParametersModule : FakeModule
    {
        public sealed record Call(CK_C_INITIALIZE_ARGS? Args, string? Reserved)
        {
            public ulong Flags => (ulong)Args!.Value.Flags;
        }

        public bool CannotLock { get; init; }
        public bool RequireParameters { get; init; }

        // Each C_Initialize's arguments and pReserved string, read while the call is in progress.
        public List<Call> Received { get; } = [];

        protected override CKR C_Initialize(IntPtr pInitArgs)
        {
            CK_C_INITIALIZE_ARGS? args = pInitArgs == IntPtr.Zero ? null : UnmanagedMemory.Read<CK_C_INITIALIZE_ARGS>(pInitArgs);
            string? reserved = args is { Reserved: var r } && r != IntPtr.Zero ? Marshal.PtrToStringUTF8(r) : null;
            Received.Add(new Call(args, reserved));

            if (RequireParameters && reserved is null)
                return CKR.CKR_ARGUMENTS_BAD;
            return CannotLock && args is { } a && ((ulong)a.Flags & CKF.CKF_OS_LOCKING_OK) != 0 ? CKR.CKR_CANT_LOCK : CKR.CKR_OK;
        }
    }
}
