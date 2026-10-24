using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// The logins the sessions of one module binding hold, slot by slot.
/// </summary>
/// <remarks>
/// <para>
/// PKCS#11 keeps the login state per application and token, not per session (v3.2 §5.6): once one session
/// has logged in, every session on the token has, a second <c>C_Login</c> answers
/// <see cref="CKR.CKR_USER_ALREADY_LOGGED_IN"/>, and one <c>C_Logout</c> logs every session out. Left alone,
/// a second logged-in session would fail to open, and disposing either would log the other out under it.
/// </para>
/// <para>
/// So each session that logs in is counted as a holder of its slot's login. A login that the token answers
/// with CKR_USER_ALREADY_LOGGED_IN is accepted when this binding already holds a login of that user type
/// there, and only the last holder to leave sends <c>C_Logout</c>. <c>C_Login</c> is still called every
/// time: the token, not this registry, decides whether a login is needed.
/// </para>
/// </remarks>
internal sealed class SlotLogins
{
    private readonly Lock _lock = new();
    private readonly Dictionary<ulong, (CKU User, int Holders)> _bySlot = [];

    /// <summary>
    /// Runs <paramref name="login"/> and, if it logged in, or found a login of <paramref name="userType"/>
    /// this binding already holds, counts the caller as a holder of <paramref name="slot"/>'s login.
    /// </summary>
    /// <returns><see cref="CKR.CKR_OK"/> when the caller now holds the login; otherwise the login's error.</returns>
    public CKR Acquire(ulong slot, CKU userType, Func<CKR> login)
    {
        lock (_lock)
        {
            CKR rv = login();
            bool held = _bySlot.TryGetValue(slot, out var current) && current.User == userType;
            if (rv == CKR.CKR_USER_ALREADY_LOGGED_IN && held)
                rv = CKR.CKR_OK;
            if (rv == CKR.CKR_OK)
                _bySlot[slot] = (userType, held ? current.Holders + 1 : 1);
            return rv;
        }
    }

    /// <summary>
    /// Drops one holder of <paramref name="slot"/>'s login.
    /// </summary>
    /// <returns><see langword="true"/> when no holder is left, so the caller sends <c>C_Logout</c>.</returns>
    public bool Release(ulong slot)
    {
        lock (_lock)
        {
            if (!_bySlot.TryGetValue(slot, out var current))
                return true;
            if (current.Holders > 1)
            {
                _bySlot[slot] = (current.User, current.Holders - 1);
                return false;
            }
            _bySlot.Remove(slot);
            return true;
        }
    }

    /// <summary>Forgets <paramref name="slot"/>'s login, which a <c>C_Logout</c> has just ended for every holder.</summary>
    public void Clear(ulong slot)
    {
        lock (_lock)
            _bySlot.Remove(slot);
    }
}
