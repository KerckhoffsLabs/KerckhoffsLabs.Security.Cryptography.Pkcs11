using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Discovery;

// Pure decoding logic — no session needed. Builds CK_SESSION_INFO native structs and asserts
// how SessionInfo decodes them.
public sealed class SessionInfoTests
{
    [Fact]
    public void Decodes_AllFields()
    {
        var native = new CK_SESSION_INFO
        {
            SlotId = (NativeCULong)4UL,
            State = (NativeCULong)(ulong)CKS.CKS_RW_USER_FUNCTIONS,
            Flags = (NativeCULong)(CKF.CKF_RW_SESSION.Value | CKF.CKF_SERIAL_SESSION.Value),
            DeviceError = (NativeCULong)0UL,
        };

        var info = new SessionInfo((NativeCULong)42UL, native);

        Assert.Equal(42UL, info.SessionId);
        Assert.Equal(4UL, info.SlotId);
        Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, info.State);
        Assert.Equal(0UL, info.DeviceError);
        Assert.True(info.SessionFlags.RwSession);
        Assert.True(info.SessionFlags.SerialSession);
    }

    [Theory]
    [InlineData(0UL, CKS.CKS_RO_PUBLIC_SESSION)]
    [InlineData(1UL, CKS.CKS_RO_USER_FUNCTIONS)]
    [InlineData(2UL, CKS.CKS_RW_PUBLIC_SESSION)]
    [InlineData(3UL, CKS.CKS_RW_USER_FUNCTIONS)]
    [InlineData(4UL, CKS.CKS_RW_SO_FUNCTIONS)]
    public void State_DecodedFromRawValue(ulong raw, CKS expected)
    {
        var native = new CK_SESSION_INFO { State = (NativeCULong)raw };
        var info = new SessionInfo((NativeCULong)0UL, native);
        Assert.Equal(expected, info.State);
    }

    [Fact]
    public void DeviceError_Preserved()
    {
        var native = new CK_SESSION_INFO { DeviceError = (NativeCULong)0xDEADUL };
        var info = new SessionInfo((NativeCULong)0UL, native);
        Assert.Equal(0xDEADUL, info.DeviceError);
    }

    [Fact]
    public void ReadOnlySession_RwSessionFlagFalse()
    {
        // SerialSession alone (the read-only case): RW flag must be false.
        var native = new CK_SESSION_INFO { Flags = (NativeCULong)CKF.CKF_SERIAL_SESSION.Value };
        var info = new SessionInfo((NativeCULong)0UL, native);
        Assert.False(info.SessionFlags.RwSession);
        Assert.True(info.SessionFlags.SerialSession);
    }
}
