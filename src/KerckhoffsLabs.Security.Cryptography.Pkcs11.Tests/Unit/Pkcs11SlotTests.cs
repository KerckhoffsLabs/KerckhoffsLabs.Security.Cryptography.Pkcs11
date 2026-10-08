using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// Unit tests for <see cref="Pkcs11Slot"/> driven through a <see cref="FakeModule"/> behind the real
/// loader — no token needed. Exercises argument validation, result wrapping, error mapping, and the
/// two-call mechanism-list probe.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11SlotTests
{
    private const ulong SlotId = 42;

    // Configurable fake: each P11 call returns a settable CKR and canned out-struct, and captures
    // the inputs the slot passed down.
    private sealed class SlotFake : SessionTestModule
    {
        public NativeCULong LastSlotId;
        public CKR SlotInfoRv = CKR.CKR_OK; public CK_SLOT_INFO SlotInfo;
        public CKR TokenInfoRv = CKR.CKR_OK; public CK_TOKEN_INFO TokenInfo;
        public CKR MechInfoRv = CKR.CKR_OK; public CK_MECHANISM_INFO MechInfo;
        public CKR InitTokenRv = CKR.CKR_OK;
        public byte[]? CapturedPin; public NativeCULong CapturedPinLen; public byte[]? CapturedLabel;
        public CKR OpenRv = CKR.CKR_OK; public NativeCULong OpenSessionId = (NativeCULong)7UL; public NativeCULong CapturedOpenFlags;

        // Mechanism-list two-call probe knobs.
        public CKR MechListRv1 = CKR.CKR_OK, MechListRv2 = CKR.CKR_OK;
        public CKM[] Mechs = [];
        public NativeCULong? FirstCallCount; // count reported on the probe call (defaults to Mechs.Length)

        protected override CKR C_GetSlotInfo(NativeCULong slotId, ref CK_SLOT_INFO info)
        { LastSlotId = slotId; info = SlotInfo; return SlotInfoRv; }
        protected override CKR C_GetTokenInfo(NativeCULong slotId, ref CK_TOKEN_INFO info)
        { LastSlotId = slotId; info = TokenInfo; return TokenInfoRv; }
        protected override CKR C_GetMechanismInfo(NativeCULong slotId, NativeCULong type, ref CK_MECHANISM_INFO info)
        { LastSlotId = slotId; info = MechInfo; return MechInfoRv; }
        protected override CKR C_GetMechanismList(NativeCULong slotId, NativeBuffer<NativeCULong> mechanismList, ref NativeCULong count)
        {
            if (mechanismList.IsNull) { count = FirstCallCount ?? (NativeCULong)Mechs.Length; return MechListRv1; }
            int n = Math.Min(mechanismList.Span.Length, Mechs.Length);
            for (int i = 0; i < n; i++) mechanismList.Span[i] = (NativeCULong)(ulong)Mechs[i];
            count = (NativeCULong)Mechs.Length; // token may report fewer than the probe (shrink)
            return MechListRv2;
        }
        protected override CKR C_InitToken(NativeCULong slotId, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> label)
        { CapturedPin = pin.ToArray(); CapturedPinLen = (NativeCULong)pin.Length; CapturedLabel = label.ToArray(); return InitTokenRv; }
        protected override CKR C_OpenSession(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session)
        { CapturedOpenFlags = flags; session = OpenSessionId; return OpenRv; }
    }

    private static Pkcs11Slot NewSlot(SlotFake fake) => new(fake.LowLevel, SlotId);

    // === Construction =====================================================

    [Fact]
    public void Ctor_NullLibrary_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new Pkcs11Slot(null!, SlotId));

    [Fact]
    public void SlotId_ReturnsConstructedValue()
    {
        using var fake = new SlotFake();
        Assert.Equal(SlotId, NewSlot(fake).SlotId.Value);
    }

    // === GetSlotInfo ======================================================

    [Fact]
    public void GetSlotInfo_Ok_WrapsResultAndPassesSlotId()
    {
        using var fake = new SlotFake { SlotInfo = new CK_SLOT_INFO { Flags = (NativeCULong)CKF.CKF_TOKEN_PRESENT } };
        var info = NewSlot(fake).GetSlotInfo();

        Assert.Equal(SlotId, (ulong)fake.LastSlotId);
        Assert.Equal(SlotId, info.SlotId.Value);
        Assert.True(info.SlotFlags.TokenPresent);
    }

    [Fact]
    public void GetSlotInfo_Error_Throws()
    {
        using var fake = new SlotFake { SlotInfoRv = CKR.CKR_DEVICE_ERROR };
        Assert.ThrowsAny<Pkcs11Exception>(() => NewSlot(fake).GetSlotInfo());
    }

    // === GetTokenInfo =====================================================

    [Fact]
    public void GetTokenInfo_Ok_WrapsResult()
    {
        using var fake = new SlotFake { TokenInfo = new CK_TOKEN_INFO { Flags = (NativeCULong)CKF.CKF_TOKEN_INITIALIZED } };
        var info = NewSlot(fake).GetTokenInfo();

        Assert.Equal(SlotId, info.SlotId.Value);
        Assert.True(info.TokenFlags.TokenInitialized);
    }

    [Fact]
    public void GetTokenInfo_Error_Throws()
    {
        using var fake = new SlotFake { TokenInfoRv = CKR.CKR_TOKEN_NOT_PRESENT };
        Assert.ThrowsAny<Pkcs11Exception>(() => NewSlot(fake).GetTokenInfo());
    }

    // === GetMechanismInfo =================================================

    [Fact]
    public void GetMechanismInfo_Ok_PreservesMechanismAndKeySizes()
    {
        using var fake = new SlotFake
        {
            MechInfo = new CK_MECHANISM_INFO
            {
                MinKeySize = (NativeCULong)128UL,
                MaxKeySize = (NativeCULong)256UL,
                Flags = (NativeCULong)CKF.CKF_ENCRYPT,
            }
        };
        var info = NewSlot(fake).GetMechanismInfo(CKM.CKM_AES_GCM);

        Assert.Equal(CKM.CKM_AES_GCM, info.Mechanism);
        Assert.Equal(128UL, info.MinKeySize);
        Assert.Equal(256UL, info.MaxKeySize);
        Assert.True(info.MechanismFlags.Encrypt);
    }

    [Fact]
    public void GetMechanismInfo_Error_Throws()
    {
        using var fake = new SlotFake { MechInfoRv = CKR.CKR_MECHANISM_INVALID };
        Assert.ThrowsAny<Pkcs11Exception>(() => NewSlot(fake).GetMechanismInfo(CKM.CKM_AES_GCM));
    }

    // === GetMechanismList (two-call probe) ================================

    [Fact]
    public void GetMechanismList_ZeroCount_ReturnsEmpty()
    {
        using var fake = new SlotFake { Mechs = [] };
        var list = NewSlot(fake).GetMechanismList();
        Assert.Empty(list);
    }

    [Fact]
    public void GetMechanismList_Populated_ReturnsAll()
    {
        using var fake = new SlotFake { Mechs = [CKM.CKM_AES_GCM, CKM.CKM_SHA256, CKM.CKM_RSA_PKCS] };
        var list = NewSlot(fake).GetMechanismList();
        CKM[] expected = [CKM.CKM_AES_GCM, CKM.CKM_SHA256, CKM.CKM_RSA_PKCS];
        Assert.Equal(expected, list);
    }

    // This method's documentation claimed for a long time that vendor-defined mechanisms without a CKM
    // member were "dropped from the result". They never were — the interop layer casts each value
    // without validating it, deliberately, so they arrive as CKM values the enum does not name. The
    // claim mattered: it told callers a mechanism was unreachable when it was sitting in the list, and
    // documentation is not the kind of thing a compiler disagrees with. Hence a test.
    [Fact]
    public void GetMechanismList_VendorDefinedMechanisms_SurviveUnnamed()
    {
        const ulong ckmIbmEthDerive = 0x80070002UL;  // no CKM member
        using var fake = new SlotFake { Mechs = [CKM.CKM_AES_GCM, (CKM)ckmIbmEthDerive] };

        var list = NewSlot(fake).GetMechanismList();

        Assert.Equal(2, list.Count);
        Assert.Equal(ckmIbmEthDerive, (ulong)list[1]);
        Assert.False(Enum.IsDefined(list[1]));            // present, but unnamed
        Assert.True(new Mechanism(list[1]).IsVendorDefined);  // and usable from here
    }

    [Fact]
    public void GetMechanismList_TokenReportsFewerOnSecondCall_ResizesDown()
    {
        // Probe says 3, the real call fills only 2 -> result must be trimmed to 2.
        using var fake = new SlotFake { FirstCallCount = (NativeCULong)3UL, Mechs = [CKM.CKM_AES_GCM, CKM.CKM_SHA256] };
        var list = NewSlot(fake).GetMechanismList();
        CKM[] expected = [CKM.CKM_AES_GCM, CKM.CKM_SHA256];
        Assert.Equal(expected, list);
    }

    [Fact]
    public void GetMechanismList_ProbeError_Throws()
    {
        using var fake = new SlotFake { MechListRv1 = CKR.CKR_DEVICE_ERROR, Mechs = [CKM.CKM_AES_GCM] };
        Assert.ThrowsAny<Pkcs11Exception>(() => NewSlot(fake).GetMechanismList());
    }

    [Fact]
    public void GetMechanismList_SecondCallError_Throws()
    {
        using var fake = new SlotFake { MechListRv2 = CKR.CKR_BUFFER_TOO_SMALL, Mechs = [CKM.CKM_AES_GCM] };
        Assert.ThrowsAny<Pkcs11Exception>(() => NewSlot(fake).GetMechanismList());
    }

    // === InitTokenWithPin ========================================================

    [Fact]
    public void InitTokenWithPin_NullPin_Throws()
    {
        using var fake = new SlotFake();
        var ex = Assert.Throws<ArgumentNullException>(() => NewSlot(fake).InitTokenWithPin(null!, "label"));
        Assert.Equal("soPin", ex.ParamName);
    }

    [Fact]
    public void InitTokenWithPin_NullLabel_Throws()
    {
        using var fake = new SlotFake();
        using var pin = new SecurePin("1234");
        var ex = Assert.Throws<ArgumentNullException>(() => NewSlot(fake).InitTokenWithPin(pin, null!));
        Assert.Equal("label", ex.ParamName);
    }

    [Fact]
    public void InitTokenWithPin_LabelTooLong_Throws()
    {
        using var fake = new SlotFake();
        using var pin = new SecurePin("1234");
        var ex = Assert.Throws<ArgumentException>(() => NewSlot(fake).InitTokenWithPin(pin, new string('a', 33)));
        Assert.Equal("label", ex.ParamName);
    }

    [Fact]
    public void InitTokenWithPin_Ok_PadsLabelToThirtyTwoSpacesAndPassesPin()
    {
        using var fake = new SlotFake();
        using var pin = new SecurePin([1, 2, 3, 4]);
        NewSlot(fake).InitTokenWithPin(pin, "tok");

        Assert.Equal(new byte[] { 1, 2, 3, 4 }, fake.CapturedPin);
        Assert.Equal(4UL, (ulong)fake.CapturedPinLen);
        Assert.NotNull(fake.CapturedLabel);
        Assert.Equal(32, fake.CapturedLabel.Length);
        Assert.Equal("tok"u8.ToArray(), fake.CapturedLabel[..3]);
        Assert.All(fake.CapturedLabel[3..], b => Assert.Equal((byte)0x20, b)); // space padding
    }

    [Fact]
    public void InitTokenWithPin_Error_Throws()
    {
        using var fake = new SlotFake { InitTokenRv = CKR.CKR_PIN_INCORRECT };
        using var pin = new SecurePin("1234");
        Assert.ThrowsAny<Pkcs11Exception>(() => NewSlot(fake).InitTokenWithPin(pin, "label"));
    }

    // === OpenSession ======================================================

    [Fact]
    public void OpenSession_ReadWrite_SetsSerialAndRwFlags()
    {
        using var fake = new SlotFake();
        var session = NewSlot(fake).OpenSession(readWrite: true);
        Assert.NotNull(session);
        Assert.Equal(CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION, (ulong)fake.CapturedOpenFlags);
        session.Dispose();
    }

    [Fact]
    public void OpenSession_ReadOnly_SetsSerialFlagOnly()
    {
        using var fake = new SlotFake();
        var session = NewSlot(fake).OpenSession(readWrite: false);
        Assert.Equal(CKF.CKF_SERIAL_SESSION, (ulong)fake.CapturedOpenFlags);
        session.Dispose();
    }

    [Fact]
    public void OpenSession_Error_Throws()
    {
        using var fake = new SlotFake { OpenRv = CKR.CKR_SESSION_COUNT };
        Assert.ThrowsAny<Pkcs11Exception>(() => NewSlot(fake).OpenSession());
    }

    [Fact]
    public void OpenSession_LogsThePolicyTheSessionEnforces()
    {
        using var fake = new SlotFake();
        var logger = new CapturingLogger();
        var slot = new Pkcs11Slot(fake.LowLevel, SlotId, new CapturingLoggerFactory(logger));

        using (slot.OpenSession(policy: CryptoPolicy.FipsOnly)) { }
        using (slot.OpenSession()) { }

        var opened = logger.Entries.Where(e => e.Level == Microsoft.Extensions.Logging.LogLevel.Information).ToList();
        Assert.Equal(2, opened.Count);
        Assert.Contains("under FipsOnly policy", opened[0].Message, StringComparison.Ordinal);
        Assert.Contains("under SecureOnly policy", opened[1].Message, StringComparison.Ordinal);
    }
}
