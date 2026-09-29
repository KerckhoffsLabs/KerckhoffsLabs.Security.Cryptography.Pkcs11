using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// The session's mechanism cache must hold only the entries the module actually returned.
/// </summary>
public sealed class Pkcs11SessionSupportsMechanismListTests
{
    // Probes a count of three, then fills one entry and reports one — as a module does when its list
    // shrinks between the two calls, or when entries it could not represent were dropped.
    private sealed class ShrinkingListFake : FakeLowLevelPkcs11Library
    {
        public override CKR C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info)
        {
            info.SlotId = (NativeCULong)1;
            return CKR.CKR_OK;
        }

        public override CKR C_GetMechanismList(NativeCULong slotId, CKM[]? mechanismList, ref NativeCULong count)
        {
            if (mechanismList is null)
            {
                count = (NativeCULong)3;
                return CKR.CKR_OK;
            }

            mechanismList[0] = CKM.CKM_AES_GCM;
            count = (NativeCULong)1;
            return CKR.CKR_OK;
        }

        public override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;
    }

    // The unused slots of the array hold default(CKM), which is CKM_RSA_PKCS_KEY_PAIR_GEN — a real
    // mechanism the module never reported.
    [Fact]
    public void SupportsMechanism_IgnoresArraySlotsBeyondTheReturnedCount()
    {
        using var session = new Pkcs11Session(new ShrinkingListFake(), sessionId: 1);

        Assert.True(session.SupportsMechanism(CKM.CKM_AES_GCM));
        Assert.False(session.SupportsMechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN));
    }
}
