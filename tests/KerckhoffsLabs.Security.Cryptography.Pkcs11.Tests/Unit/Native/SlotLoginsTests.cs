using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// The per-slot login count behind several logged-in sessions on one token: the token's answer decides each
/// login, CKR_USER_ALREADY_LOGGED_IN counts only for a login this binding already holds, and only the last
/// holder is told to log out.
/// </summary>
public sealed class SlotLoginsTests
{
    private const ulong Slot = 7;

    [Fact]
    public void SecondLogin_AlreadyLoggedIn_ForTheHeldUserType_IsAHolder()
    {
        var logins = new SlotLogins();

        Assert.Equal(CKR.CKR_OK, logins.Acquire(Slot, CKU.CKU_USER, () => CKR.CKR_OK));
        Assert.Equal(CKR.CKR_OK, logins.Acquire(Slot, CKU.CKU_USER, () => CKR.CKR_USER_ALREADY_LOGGED_IN));

        Assert.False(logins.Release(Slot));
        Assert.True(logins.Release(Slot));
    }

    // A login this binding never made (another user type, or no record at all) keeps the module's answer.
    [Fact]
    public void AlreadyLoggedIn_WithoutAHeldLogin_OfThatUserType_IsTheModulesError()
    {
        var logins = new SlotLogins();
        Assert.Equal(CKR.CKR_USER_ALREADY_LOGGED_IN, logins.Acquire(Slot, CKU.CKU_USER, () => CKR.CKR_USER_ALREADY_LOGGED_IN));

        Assert.Equal(CKR.CKR_OK, logins.Acquire(Slot, CKU.CKU_SO, () => CKR.CKR_OK));
        Assert.Equal(CKR.CKR_USER_ALREADY_LOGGED_IN, logins.Acquire(Slot, CKU.CKU_USER, () => CKR.CKR_USER_ALREADY_LOGGED_IN));
    }

    [Fact]
    public void FailedLogin_HoldsNothing()
    {
        var logins = new SlotLogins();

        Assert.Equal(CKR.CKR_PIN_INCORRECT, logins.Acquire(Slot, CKU.CKU_USER, () => CKR.CKR_PIN_INCORRECT));

        Assert.Equal(CKR.CKR_USER_ALREADY_LOGGED_IN, logins.Acquire(Slot, CKU.CKU_USER, () => CKR.CKR_USER_ALREADY_LOGGED_IN));
    }

    // Slots are counted apart: logging out of one leaves the other's holders alone.
    [Fact]
    public void Slots_AreCountedApart()
    {
        var logins = new SlotLogins();
        logins.Acquire(Slot, CKU.CKU_USER, () => CKR.CKR_OK);
        logins.Acquire(Slot + 1, CKU.CKU_USER, () => CKR.CKR_OK);
        logins.Acquire(Slot + 1, CKU.CKU_USER, () => CKR.CKR_USER_ALREADY_LOGGED_IN);

        Assert.True(logins.Release(Slot));
        Assert.False(logins.Release(Slot + 1));
    }

    // A C_Logout ends the login for every holder; the next login starts a fresh count.
    [Fact]
    public void Clear_ForgetsEveryHolder()
    {
        var logins = new SlotLogins();
        logins.Acquire(Slot, CKU.CKU_USER, () => CKR.CKR_OK);
        logins.Acquire(Slot, CKU.CKU_USER, () => CKR.CKR_USER_ALREADY_LOGGED_IN);

        logins.Clear(Slot);

        Assert.Equal(CKR.CKR_USER_ALREADY_LOGGED_IN, logins.Acquire(Slot, CKU.CKU_USER, () => CKR.CKR_USER_ALREADY_LOGGED_IN));
        Assert.True(logins.Release(Slot));
    }
}
