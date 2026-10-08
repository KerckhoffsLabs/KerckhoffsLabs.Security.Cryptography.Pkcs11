using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native.Dispatch;

/// <summary>
/// The session wrappers (open and close, PINs and login, session information and operation state, and the
/// v3.x cancel, user login and validation flags), called through a module's function table: each reaches
/// the module with its arguments and returns what the module writes, and <c>C_GetOperationState</c>
/// follows the output rules of PKCS#11 v3.2 §5.2.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class SessionDispatchTests
{
    private static readonly byte[] Pin = [0x31, 0x32, 0x33, 0x34];
    private static readonly byte[] State = [0x51, 0x52, 0x53, 0x54];
    private const ulong Slot = 2;
    private const ulong Opened = 0x99;

    private static readonly Dictionary<string, DispatchCase> Cases = new DispatchCase[]
    {
        new(nameof(LowLevelPkcs11Library.C_InitPIN), l => l.C_InitPIN(DispatchSmoke.Session, Pin)),
        new(nameof(LowLevelPkcs11Library.C_SetPIN), l => l.C_SetPIN(DispatchSmoke.Session, Pin, Pin)),
        new(nameof(LowLevelPkcs11Library.C_OpenSession), l =>
        {
            NativeCULong session = default;
            CKR rv = l.C_OpenSession((NativeCULong)Slot, (NativeCULong)(ulong)CKF.CKF_SERIAL_SESSION, ref session);
            return rv == CKR.CKR_OK && (ulong)session != Opened ? CKR.CKR_GENERAL_ERROR : rv;
        }),
        new(nameof(LowLevelPkcs11Library.C_CloseSession), l => l.C_CloseSession(DispatchSmoke.Session)),
        new(nameof(LowLevelPkcs11Library.C_CloseAllSessions), l => l.C_CloseAllSessions((NativeCULong)Slot)),
        new(nameof(LowLevelPkcs11Library.C_GetSessionInfo), l =>
        {
            CK_SESSION_INFO info = default;
            CKR rv = l.C_GetSessionInfo(DispatchSmoke.Session, ref info);
            return rv == CKR.CKR_OK && ((ulong)info.SlotId != Slot || (ulong)info.State != 3 || (ulong)info.Flags != 6) ? CKR.CKR_GENERAL_ERROR : rv;
        }),
        new(nameof(LowLevelPkcs11Library.C_GetOperationState), l => l.C_GetOperationState(DispatchSmoke.Session, new byte[8], lengthOnly: false, out _)),
        new(nameof(LowLevelPkcs11Library.C_SetOperationState), l => l.C_SetOperationState(DispatchSmoke.Session, State, (NativeCULong)3, (NativeCULong)4)),
        new(nameof(LowLevelPkcs11Library.C_Login), l => l.C_Login(DispatchSmoke.Session, CKU.CKU_USER, Pin)),
        new(nameof(LowLevelPkcs11Library.C_LoginUser), l => l.C_LoginUser(DispatchSmoke.Session, CKU.CKU_USER, Pin, "alice"u8)),
        new(nameof(LowLevelPkcs11Library.C_Logout), l => l.C_Logout(DispatchSmoke.Session)),
        new(nameof(LowLevelPkcs11Library.C_SessionCancel), l => l.C_SessionCancel(DispatchSmoke.Session, (NativeCULong)(ulong)CKF.CKF_SIGN)),
        new(nameof(LowLevelPkcs11Library.C_GetSessionValidationFlags), l =>
        {
            NativeCULong flags = default;
            CKR rv = l.C_GetSessionValidationFlags(DispatchSmoke.Session, (NativeCULong)0, ref flags);
            return rv == CKR.CKR_OK && (ulong)flags != 0x10 ? CKR.CKR_GENERAL_ERROR : rv;
        }),
    }.ToDictionary(c => c.Function, StringComparer.Ordinal);

    public static TheoryData<string> Functions => [.. Cases.Keys];

    private static readonly HashSet<string> TakesPin =
    [
        nameof(LowLevelPkcs11Library.C_InitPIN), nameof(LowLevelPkcs11Library.C_SetPIN),
        nameof(LowLevelPkcs11Library.C_Login), nameof(LowLevelPkcs11Library.C_LoginUser),
    ];

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_ReachesTheModule_WithItsArguments_AndReturnsItsResults(string function)
    {
        using var module = new SessionModule();

        Assert.Equal(CKR.CKR_OK, DispatchSmoke.ReachesTheModule(module, Cases[function]));

        bool bySlot = function is nameof(LowLevelPkcs11Library.C_OpenSession) or nameof(LowLevelPkcs11Library.C_CloseAllSessions);
        Assert.Equal(bySlot ? Slot : (ulong)DispatchSmoke.Session, module.LastHandle);
        if (TakesPin.Contains(function))
            Assert.Equal(Pin, module.LastPin);
    }

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_OfAFunctionTheModuleLacks_ReturnsNotSupported(string function)
        => DispatchSmoke.ReportsAMissingFunctionUnsupported(Cases[function]);

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_AfterDispose_Throws_WithoutReachingTheModule(string function)
    {
        using var module = new SessionModule();
        DispatchSmoke.RefusesACallAfterDispose(module, Cases[function]);
    }

    [Fact]
    public void Login_PassesTheUserType()
    {
        using var module = new SessionModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        lowLevel.C_Login(DispatchSmoke.Session, CKU.CKU_SO, Pin);

        Assert.Equal((ulong)CKU.CKU_SO, module.LastUserType);
    }

    [Fact]
    public void GetOperationState_LengthQuery_SendsNoBuffer_AndReturnsTheLength()
    {
        using var module = new SessionModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        CKR rv = lowLevel.C_GetOperationState(DispatchSmoke.Session, new byte[16], lengthOnly: true, out NativeCULong length);

        Assert.Equal(CKR.CKR_OK, rv);
        Assert.True(module.OutputWasNull);
        Assert.Equal((ulong)State.Length, (ulong)length);
    }

    [Fact]
    public void GetOperationState_Fill_WritesTheState()
    {
        using var module = new SessionModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        byte[] output = new byte[16];

        CKR rv = lowLevel.C_GetOperationState(DispatchSmoke.Session, output, lengthOnly: false, out NativeCULong length);

        Assert.Equal(CKR.CKR_OK, rv);
        Assert.False(module.OutputWasNull);
        Assert.Equal(State, output.AsSpan(0, (int)(ulong)length).ToArray());
    }

    [Fact]
    public void GetOperationState_FillReportingMoreThanTheBuffer_IsRefused()
    {
        using var module = new SessionModule { OverReports = true };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        Assert.Throws<Pkcs11UnclassifiedException>(() => lowLevel.C_GetOperationState(DispatchSmoke.Session, new byte[16], lengthOnly: false, out _));
    }

    [Fact]
    public void GetOperationState_LengthQueryReportingUnavailableInformation_IsRefused()
    {
        using var module = new SessionModule { QueryReports = NativeCULong.MaxValue };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        Assert.Throws<Pkcs11UnclassifiedException>(() => lowLevel.C_GetOperationState(DispatchSmoke.Session, default, lengthOnly: true, out _));
    }

    /// <summary>Implements the whole session family and records what each call received.</summary>
    private sealed class SessionModule : FakeModule
    {
        public bool OverReports { get; init; }
        public NativeCULong? QueryReports { get; init; }

        public ulong LastHandle { get; private set; }
        public byte[]? LastPin { get; private set; }
        public ulong LastUserType { get; private set; }
        public bool OutputWasNull { get; private set; }

        protected override CKR C_InitPIN(NativeCULong session, ReadOnlySpan<byte> pin) => Pinned(session, pin);
        protected override CKR C_SetPIN(NativeCULong session, ReadOnlySpan<byte> oldPin, ReadOnlySpan<byte> newPin) => Pinned(session, newPin);

        protected override CKR C_OpenSession(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session)
        {
            session = (NativeCULong)Opened;
            return Received(slotId);
        }

        protected override CKR C_CloseSession(NativeCULong session) => Received(session);
        protected override CKR C_CloseAllSessions(NativeCULong slotId) => Received(slotId);

        protected override CKR C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info)
        {
            info.SlotId = (NativeCULong)Slot;
            info.State = (NativeCULong)3;
            info.Flags = (NativeCULong)6;
            return Received(session);
        }

        protected override CKR C_GetOperationState(NativeCULong session, NativeBuffer<byte> operationState, ref NativeCULong operationStateLen)
        {
            Received(session);
            OutputWasNull = operationState.IsNull;
            if (operationState.IsNull)
            {
                operationStateLen = QueryReports ?? (NativeCULong)(ulong)State.Length;
                return CKR.CKR_OK;
            }
            State.CopyTo(operationState.Span);
            operationStateLen = (NativeCULong)(ulong)(OverReports ? operationState.Span.Length + 1 : State.Length);
            return CKR.CKR_OK;
        }

        protected override CKR C_SetOperationState(NativeCULong session, ReadOnlySpan<byte> operationState, NativeCULong encryptionKey, NativeCULong authenticationKey)
            => Received(session);

        protected override CKR C_Login(NativeCULong session, NativeCULong userType, ReadOnlySpan<byte> pin)
        {
            LastUserType = (ulong)userType;
            return Pinned(session, pin);
        }

        protected override CKR C_LoginUser(NativeCULong session, NativeCULong userType, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> username)
            => Pinned(session, pin);

        protected override CKR C_Logout(NativeCULong session) => Received(session);
        protected override CKR C_SessionCancel(NativeCULong session, NativeCULong flags) => Received(session);

        protected override CKR C_GetSessionValidationFlags(NativeCULong session, NativeCULong type, ref NativeCULong flags)
        {
            flags = (NativeCULong)0x10;
            return Received(session);
        }

        private CKR Pinned(NativeCULong session, ReadOnlySpan<byte> pin)
        {
            LastPin = pin.ToArray();
            return Received(session);
        }

        private CKR Received(NativeCULong handle)
        {
            LastHandle = (ulong)handle;
            return CKR.CKR_OK;
        }
    }
}
