using System.Security.Cryptography;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sessions;

/// <summary>
/// What a real module reports about its slot, token, mechanisms and sessions, and how it runs the login
/// state machine, checked on every backend: the information the library parses and acts on (a token found by
/// label, a mechanism list gated on, a session's state), and the return codes it maps for sessions and logins.
/// </summary>
/// <remarks>
/// Nothing here changes the fixture's token beyond its own objects: a wrong PIN is tried once and followed by
/// the right one at once, so no token counts towards a lockout; no PIN is changed; SO is never logged in.
/// </remarks>
internal static class SessionConformanceTestCases
{
    private static Pkcs11Slot Slot(IPkcs11Backend backend)
        => backend.Library.GetSlotList().First(s => (NativeCULong)s.SlotId.Value == backend.SlotId);

    private static void AssertRv(CKR expected, CKR actual, string call) =>
        Assert.True(actual == expected, $"{call} was expected to return {expected} but returned {actual}.");

    private static void AssertNoNul(string value, string field) =>
        Assert.False(value.Contains('\0', StringComparison.Ordinal), $"{field} \"{value.Replace("\0", "\\0", StringComparison.Ordinal)}\" holds NUL padding; PKCS#11 pads with spaces.");

    // Opens a session through the raw dispatch, so the test sees the module's own answers to the session and
    // login calls rather than the library's handling of them.
    private static NativeCULong OpenRawSession(LowLevelPkcs11Library lowLevel, NativeCULong slot, bool readWrite = true)
    {
        ulong flags = CKF.CKF_SERIAL_SESSION | (readWrite ? CKF.CKF_RW_SESSION : 0UL);
        AssertRv(CKR.CKR_OK, lowLevel.C_OpenSession(slot, (NativeCULong)flags, out NativeCULong session), "C_OpenSession");
        return session;
    }

    private static CK_SESSION_INFO SessionInfo(LowLevelPkcs11Library lowLevel, NativeCULong session)
    {
        AssertRv(CKR.CKR_OK, lowLevel.C_GetSessionInfo(session, out CK_SESSION_INFO info), "C_GetSessionInfo");
        return info;
    }

    // Ends any login the token holds, from a session of its own, so a case starts from the public state.
    private static void LogOutTheToken(LowLevelPkcs11Library lowLevel, NativeCULong slot)
    {
        NativeCULong session = OpenRawSession(lowLevel, slot);
        try
        {
            CKR rv = lowLevel.C_Logout(session);
            Assert.True(rv is CKR.CKR_OK or CKR.CKR_USER_NOT_LOGGED_IN, $"C_Logout returned {rv}.");
        }
        finally { lowLevel.C_CloseSession(session); }
    }

    // === Slot, token and library information ===================================

    // The fixture's slot holds an initialised token whose label is the one the fixture gave it, exactly: the
    // library finds tokens by label. Every fixed-length string is padded with spaces (§3.2), not NULs, the
    // flags are consistent, and a token that says it has a random number generator answers C_GenerateRandom.
    internal static void Assert_SlotAndTokenInfo_AreConsistent(IPkcs11Backend backend, bool requireUserPinInitialized = true)
    {
        Pkcs11Slot slot = Slot(backend);
        SlotInfo slotInfo = slot.GetSlotInfo();
        Assert.True(slotInfo.SlotFlags.TokenPresent, "The fixture's slot reports no token present.");
        AssertNoNul(slotInfo.SlotDescription, "The slot description");
        AssertNoNul(slotInfo.ManufacturerId, "The slot's manufacturer");

        TokenInfo token = slot.GetTokenInfo();
        AssertNoNul(token.Label, "The token label");
        AssertNoNul(token.ManufacturerId, "The token's manufacturer");
        AssertNoNul(token.Model, "The token model");
        AssertNoNul(token.SerialNumber, "The token serial number");
        Assert.Equal(backend.TokenLabel, token.Label);
        Assert.True(token.TokenFlags.TokenInitialized, "The fixture's token is not CKF_TOKEN_INITIALIZED.");
        if (backend.RequiresUserLogin && requireUserPinInitialized)
            Assert.True(token.TokenFlags.UserPinInitialized, "The fixture's token is not CKF_USER_PIN_INITIALIZED.");
        Assert.False(token.TokenFlags.UserPinLocked && token.TokenFlags.UserPinFinalTry, "The token reports the user PIN both locked and on its final try.");
        if (token.MaxPinLen != CK.CK_UNAVAILABLE_INFORMATION && token.MaxPinLen != 0)
            Assert.True(token.MinPinLen <= token.MaxPinLen, $"The token's ulMinPinLen {token.MinPinLen} exceeds its ulMaxPinLen {token.MaxPinLen}.");

        LibraryInfo library = backend.Library.GetInfo();
        AssertNoNul(library.ManufacturerId, "The library's manufacturer");
        AssertNoNul(library.LibraryDescription, "The library description");

        if (token.TokenFlags.Rng)
        {
            using var session = backend.OpenSession();
            Assert.Equal(32, session.GenerateRandom(32).Length);
        }
    }

    // C_GetMechanismList lists each mechanism once, C_GetMechanismInfo answers for every one of them with a key
    // size range that is a range, and a mechanism type no module defines is CKR_MECHANISM_INVALID.
    internal static void Assert_MechanismList_IsConsistent(IPkcs11Backend backend)
    {
        Pkcs11Slot slot = Slot(backend);
        IReadOnlyList<CKM> mechanisms = slot.GetMechanismList();
        Assert.NotEmpty(mechanisms);
        Assert.Equal(mechanisms.Count, mechanisms.Distinct().Count());

        foreach (CKM mechanism in mechanisms)
        {
            MechanismInfo info = slot.GetMechanismInfo(mechanism);
            Assert.Equal(mechanism, info.Mechanism);
            if (info.MaxKeySize != 0)
                Assert.True(info.MinKeySize <= info.MaxKeySize, $"{mechanism}: ulMinKeySize {info.MinKeySize} exceeds ulMaxKeySize {info.MaxKeySize}.");
        }

        // Inside the standard range and defined by no PKCS#11 version.
        const CKM Undefined = (CKM)0x7FFF_FF00UL;
        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => slot.GetMechanismInfo(Undefined));
        Assert.Equal(CKR.CKR_MECHANISM_INVALID, ex.ReturnValue);
    }

    // === Session information and states ========================================

    // A session's state follows the token's login (§5.6): read/write or read-only, public or user. A login is
    // token-wide, so it changes the state of every session of the token, and so does the logout.
    internal static void Assert_SessionStates_FollowTheTokensLogin(IPkcs11Backend backend)
    {
        LowLevelPkcs11Library lowLevel = backend.Library.LowLevelLibrary!;
        LogOutTheToken(lowLevel, backend.SlotId);

        NativeCULong rw = OpenRawSession(lowLevel, backend.SlotId);
        NativeCULong ro = OpenRawSession(lowLevel, backend.SlotId, readWrite: false);
        try
        {
            CK_SESSION_INFO info = SessionInfo(lowLevel, rw);
            Assert.Equal(backend.SlotId, info.SlotId);
            Assert.True(((ulong)info.Flags & CKF.CKF_SERIAL_SESSION) != 0, "A session without CKF_SERIAL_SESSION.");
            Assert.True(((ulong)info.Flags & CKF.CKF_RW_SESSION) != 0, "A read/write session without CKF_RW_SESSION.");
            Assert.Equal(CKS.CKS_RW_PUBLIC_SESSION, (CKS)(ulong)info.State);
            info = SessionInfo(lowLevel, ro);
            Assert.True(((ulong)info.Flags & CKF.CKF_RW_SESSION) == 0, "A read-only session with CKF_RW_SESSION.");
            Assert.Equal(CKS.CKS_RO_PUBLIC_SESSION, (CKS)(ulong)info.State);

            if (!backend.RequiresUserLogin)
                return;

            AssertRv(CKR.CKR_OK, lowLevel.C_Login(rw, CKU.CKU_USER, backend.UserPin.Span), "C_Login");
            Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, (CKS)(ulong)SessionInfo(lowLevel, rw).State);
            Assert.Equal(CKS.CKS_RO_USER_FUNCTIONS, (CKS)(ulong)SessionInfo(lowLevel, ro).State);

            AssertRv(CKR.CKR_OK, lowLevel.C_Logout(ro), "C_Logout from the other session");
            Assert.Equal(CKS.CKS_RW_PUBLIC_SESSION, (CKS)(ulong)SessionInfo(lowLevel, rw).State);
            Assert.Equal(CKS.CKS_RO_PUBLIC_SESSION, (CKS)(ulong)SessionInfo(lowLevel, ro).State);
        }
        finally
        {
            lowLevel.C_CloseSession(ro);
            lowLevel.C_CloseSession(rw);
        }
    }

    // === The login state machine ===============================================

    // A second login of the user, from the same session or from another session of the token, is
    // CKR_USER_ALREADY_LOGGED_IN; a logout of a token nobody is logged in to is CKR_USER_NOT_LOGGED_IN. The
    // library maps both to its authentication exceptions and tolerates the second on Dispose.
    internal static void Assert_LoginStateMachine_AnswersAsSpecified(IPkcs11Backend backend, CKR logoutWithNobodyLoggedIn = CKR.CKR_USER_NOT_LOGGED_IN)
    {
        LowLevelPkcs11Library lowLevel = backend.Library.LowLevelLibrary!;
        LogOutTheToken(lowLevel, backend.SlotId);

        NativeCULong first = OpenRawSession(lowLevel, backend.SlotId);
        NativeCULong second = OpenRawSession(lowLevel, backend.SlotId);
        try
        {
            AssertRv(logoutWithNobodyLoggedIn, lowLevel.C_Logout(first), "C_Logout with nobody logged in");

            AssertRv(CKR.CKR_OK, lowLevel.C_Login(first, CKU.CKU_USER, backend.UserPin.Span), "C_Login");
            AssertRv(CKR.CKR_USER_ALREADY_LOGGED_IN, lowLevel.C_Login(first, CKU.CKU_USER, backend.UserPin.Span), "a second C_Login in the same session");
            AssertRv(CKR.CKR_USER_ALREADY_LOGGED_IN, lowLevel.C_Login(second, CKU.CKU_USER, backend.UserPin.Span), "a C_Login from another session");

            AssertRv(CKR.CKR_OK, lowLevel.C_Logout(first), "C_Logout");
            AssertRv(CKR.CKR_OK, lowLevel.C_Login(second, CKU.CKU_USER, backend.UserPin.Span), "C_Login after the logout");
            AssertRv(CKR.CKR_OK, lowLevel.C_Logout(second), "C_Logout");
        }
        finally
        {
            lowLevel.C_CloseSession(second);
            lowLevel.C_CloseSession(first);
        }
    }

    // A wrong PIN is CKR_PIN_INCORRECT and logs nobody in; the right PIN right after it does. Tried once, and
    // followed at once by a successful login, so no token's retry counter is left lowered. The exception the
    // library raises for it does not carry the PIN.
    internal static void Assert_WrongPin_IsPinIncorrect_AndTheRightOneStillLogsIn(IPkcs11Backend backend)
    {
        LowLevelPkcs11Library lowLevel = backend.Library.LowLevelLibrary!;
        LogOutTheToken(lowLevel, backend.SlotId);

        byte[] wrong = [.. backend.UserPin.Span];
        wrong[^1] ^= 0x01;
        NativeCULong session = OpenRawSession(lowLevel, backend.SlotId);
        try
        {
            AssertRv(CKR.CKR_PIN_INCORRECT, lowLevel.C_Login(session, CKU.CKU_USER, wrong), "C_Login with a wrong PIN");
            Assert.Equal(CKS.CKS_RW_PUBLIC_SESSION, (CKS)(ulong)SessionInfo(lowLevel, session).State);
            AssertRv(CKR.CKR_OK, lowLevel.C_Login(session, CKU.CKU_USER, backend.UserPin.Span), "C_Login with the right PIN");
            AssertRv(CKR.CKR_OK, lowLevel.C_Logout(session), "C_Logout");
        }
        finally { lowLevel.C_CloseSession(session); }

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() =>
        {
            using var pin = new SecurePin(wrong);
            using var opened = backend.Library.OpenSessionWithPin(backend.TokenLabel, CKU.CKU_USER, pin);
        });
        Assert.Equal(CKR.CKR_PIN_INCORRECT, ex.ReturnValue);
        Assert.DoesNotContain(System.Text.Encoding.UTF8.GetString(wrong), ex.ToString(), StringComparison.Ordinal);
        using (var pin = new SecurePin(backend.UserPin.Span))
        using (var opened = backend.Library.OpenSessionWithPin(backend.TokenLabel, CKU.CKU_USER, pin))
            Assert.Equal(16, opened.GenerateRandom(16).Length);
    }

    // === Access without a login ================================================

    // With nobody logged in, a session sees the token's public objects and none of its private ones (§4.4.1),
    // and the search itself succeeds. The objects are token objects created for the case and destroyed after it.
    internal static void Assert_PrivateObjects_AreHiddenWithoutALogin(IPkcs11Backend backend)
    {
        if (!backend.RequiresUserLogin || !backend.SupportsTokenObjects)
            Assert.Skip("The backend has no login, or no token objects.");

        string label = $"kl-visibility-{Guid.NewGuid():N}";
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
        using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
        byte[] publicValue = RandomNumberGenerator.GetBytes(8);
        using (var session = TestKeys.OpenLoggedInSession(backend))
        {
            CreateTokenDataObject(session, label, isPrivate: false, publicValue);
            CreateTokenDataObject(session, label, isPrivate: true);
            TestKeys.LogoutIfRequired(backend, session);
        }

        try
        {
            using var anonymous = Slot(backend).OpenSessionCore();
            // Told apart by value: a module may number its token objects anew in every session.
            ObjectHandle found = Assert.Single(anonymous.FindAllObjects([attrClass, attrLabel]));
            using var read = anonymous.GetAttributeValue(found, [CKA.CKA_VALUE]);
            Assert.Equal(publicValue, read[0].GetValueAsByteArray());
        }
        finally
        {
            // Found again by label: a module may hand out new handles for its private objects after a login.
            using var session = TestKeys.OpenLoggedInSession(backend);
            foreach (ObjectHandle handle in session.FindAllObjects([attrClass, attrLabel]))
                session.DestroyObject(handle);
            TestKeys.LogoutIfRequired(backend, session);
        }
    }

    private static ObjectHandle CreateTokenDataObject(Pkcs11SessionCore session, string label, bool isPrivate, byte[]? value = null)
    {
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, true);
        using var attrPrivate = new ObjectAttribute(CKA.CKA_PRIVATE, isPrivate);
        using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
        using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, value ?? RandomNumberGenerator.GetBytes(8));
        return session.CreateObject([attrClass, attrToken, attrPrivate, attrLabel, attrValue]);
    }

    // A read-only session creates no token object (CKR_SESSION_READ_ONLY, §5.7) but may create a session one.
    internal static void Assert_ReadOnlySession_RefusesTokenObjects(IPkcs11Backend backend)
    {
        if (!backend.SupportsTokenObjects)
            Assert.Skip("The backend has no token objects.");

        using var session = Slot(backend).OpenSessionCore(readWrite: false);
        if (backend.RequiresUserLogin)
        {
            using var pin = new SecurePin(backend.UserPin.Span);
            session.Login(CKU.CKU_USER, pin);
        }
        try
        {
            string label = $"kl-ro-{Guid.NewGuid():N}";
            var ex = Assert.ThrowsAny<Pkcs11Exception>(() => CreateTokenDataObject(session, label, isPrivate: false));
            Assert.Equal(CKR.CKR_SESSION_READ_ONLY, ex.ReturnValue);

            using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
            using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            ObjectHandle sessionObject = session.CreateObject([attrClass, attrToken, attrLabel]);
            session.DestroyObject(sessionObject);
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    // === Handles ===============================================================

    // A closed session's handle is CKR_SESSION_HANDLE_INVALID, as is one no module handed out, and a slot id
    // that names no slot is CKR_SLOT_ID_INVALID (§5.1.6). Nothing is opened between the close and the probe, so
    // a module that hands handles out again has nothing to give the old one to.
    // randomChecksTheSession records a backend whose C_GenerateRandom does not look at the session handle.
    internal static void Assert_StaleHandles_AreRefused(IPkcs11Backend backend, bool randomChecksTheSession = true)
    {
        LowLevelPkcs11Library lowLevel = backend.Library.LowLevelLibrary!;
        NativeCULong session = OpenRawSession(lowLevel, backend.SlotId);
        AssertRv(CKR.CKR_OK, lowLevel.C_CloseSession(session), "C_CloseSession");
        AssertRv(CKR.CKR_SESSION_HANDLE_INVALID, lowLevel.C_GetSessionInfo(session, out _), "C_GetSessionInfo on a closed session");
        AssertRv(randomChecksTheSession ? CKR.CKR_SESSION_HANDLE_INVALID : CKR.CKR_OK, lowLevel.C_GenerateRandom(session, new byte[8]), "C_GenerateRandom on a closed session");
        AssertRv(CKR.CKR_SESSION_HANDLE_INVALID, lowLevel.C_GetSessionInfo((NativeCULong)0x7EADBEEFUL, out _), "C_GetSessionInfo on a handle never handed out");
        AssertRv(CKR.CKR_SLOT_ID_INVALID, lowLevel.C_OpenSession((NativeCULong)0x7EADBEEFUL, (NativeCULong)CKF.CKF_SERIAL_SESSION, out _), "C_OpenSession on a slot that does not exist");
    }

    // A session object belongs to the application, not to the session that made it (§4.4.1): another session
    // sees it while the first is open, and nobody does once the first is closed.
    internal static void Assert_SessionObject_OutlivesNoSessionOfIts(IPkcs11Backend backend)
    {
        string label = $"kl-session-object-{Guid.NewGuid():N}";
        using var other = TestKeys.OpenLoggedInSession(backend);
        try
        {
            using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
            using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            using (var creator = Slot(backend).OpenSessionCore())
            {
                using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
                using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, RandomNumberGenerator.GetBytes(8));
                ObjectHandle created = creator.CreateObject([attrClass, attrToken, attrLabel, attrValue]);
                Assert.Equal([created.ObjectId], other.FindAllObjects([attrClass, attrLabel]).Select(h => h.ObjectId));
            }
            Assert.Empty(other.FindAllObjects([attrClass, attrLabel]));
        }
        finally { TestKeys.LogoutIfRequired(backend, other); }
    }

    // === The library ===========================================================

    // A second Pkcs11Library over the same module works alongside the first: the module answers its
    // C_Initialize with CKR_CRYPTOKI_ALREADY_INITIALIZED, which the library takes, and disposing it does not
    // call C_Finalize under the first.
    internal static void Assert_SecondLibraryInstance_LeavesTheFirstWorking(IPkcs11Backend backend)
    {
        using (var second = Pkcs11Library.Load(backend.LibraryPath))
        {
            Assert.Contains(second.GetSlotList(), s => (NativeCULong)s.SlotId.Value == backend.SlotId);
            Assert.Equal(backend.Library.GetInfo().LibraryDescription, second.GetInfo().LibraryDescription);
        }

        using var session = backend.OpenSession();
        Assert.Equal(16, session.GenerateRandom(16).Length);
    }
}
