using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support;

/// <summary>
/// The pattern for code that may run while another part of the process holds the login: share the login held, or log
/// in when there is none. A second <see cref="Pkcs11Slot.Login"/> is refused (<c>CKR_USER_ALREADY_LOGGED_IN</c>, no
/// PIN sent), so a login that lost the race to another thread's shares that one instead.
/// </summary>
internal static class SlotLogins
{
    public static Pkcs11Login ShareOrLogIn(this Pkcs11Slot slot, TokenUser user, SecurePin pin)
    {
        while (true)
        {
            if (slot.TryShareLogin(user, out Pkcs11Login? shared))
                return shared;
            try
            {
                return slot.Login(user, pin);
            }
            catch (Pkcs11AuthenticationException ex) when (ex.ReturnValue == CKR.CKR_USER_ALREADY_LOGGED_IN)
            {
                // Another thread logged in first: share its login.
            }
        }
    }
}
