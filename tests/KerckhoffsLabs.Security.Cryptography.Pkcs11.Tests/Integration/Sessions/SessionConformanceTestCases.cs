using System.Security.Cryptography;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
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
/// the right one at once, so no token counts towards a lockout; no PIN is changed (a C_SetPIN to a PIN of a
/// length the token refuses is undone if the token takes it); the SO logs in with the right PIN only, and is
/// logged out again whatever fails.
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

    // The SO and the user exclude each other: with the SO logged in, C_Login(CKU_USER) from any session answers
    // CKR_USER_ANOTHER_ALREADY_LOGGED_IN, and with the user logged in so does C_Login(CKU_SO) (§5.1.6), and the
    // sessions stay in the state of whoever is logged in. The SO logs in from read/write sessions only (§5.6.8:
    // a read-only one would be CKR_SESSION_READ_ONLY_EXISTS), and nobody is logged in afterwards, whatever fails.
    internal static void Assert_SoAndUser_ExcludeEachOther(IPkcs11Backend backend)
    {
        if (!backend.RequiresUserLogin)
            Assert.Skip("The backend has no login.");
        LowLevelPkcs11Library lowLevel = backend.Library.LowLevelLibrary!;
        LogOutTheToken(lowLevel, backend.SlotId);

        NativeCULong first = OpenRawSession(lowLevel, backend.SlotId);
        NativeCULong second = OpenRawSession(lowLevel, backend.SlotId);
        try
        {
            AssertRv(CKR.CKR_OK, lowLevel.C_Login(first, CKU.CKU_SO, backend.SoPin.Span), "C_Login as the SO");
            Assert.Equal(CKS.CKS_RW_SO_FUNCTIONS, (CKS)(ulong)SessionInfo(lowLevel, second).State);
            AssertRv(CKR.CKR_USER_ANOTHER_ALREADY_LOGGED_IN, lowLevel.C_Login(first, CKU.CKU_USER, backend.UserPin.Span), "C_Login as the user in the SO's session");
            AssertRv(CKR.CKR_USER_ANOTHER_ALREADY_LOGGED_IN, lowLevel.C_Login(second, CKU.CKU_USER, backend.UserPin.Span), "C_Login as the user from another session");
            Assert.Equal(CKS.CKS_RW_SO_FUNCTIONS, (CKS)(ulong)SessionInfo(lowLevel, first).State);
            AssertRv(CKR.CKR_OK, lowLevel.C_Logout(second), "C_Logout of the SO");

            AssertRv(CKR.CKR_OK, lowLevel.C_Login(first, CKU.CKU_USER, backend.UserPin.Span), "C_Login as the user");
            AssertRv(CKR.CKR_USER_ANOTHER_ALREADY_LOGGED_IN, lowLevel.C_Login(second, CKU.CKU_SO, backend.SoPin.Span), "C_Login as the SO with the user logged in");
            Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, (CKS)(ulong)SessionInfo(lowLevel, second).State);
        }
        finally
        {
            lowLevel.C_Logout(first);
            lowLevel.C_CloseSession(second);
            lowLevel.C_CloseSession(first);
        }
    }

    // The SO makes no private object: "Only public objects can be created unless the normal user is logged in"
    // (§5.7.1), so with the SO logged in C_CreateObject with CKA_PRIVATE = TRUE answers CKR_USER_NOT_LOGGED_IN
    // (§5.1.6) and makes nothing. Nobody is logged in afterwards, whatever fails.
    // Whether the SO may see the user's private objects is left out: [PKCS11-UG] gives the "R/W SO Functions"
    // state the public objects only, but the specification itself says no more than that a private object needs
    // "the user" authenticated (§4.4), and Kryoptic, BouncyHsm, Craton HSM and FreeHSM all show the SO them.
    internal static void Assert_So_CreatesNoPrivateObject(IPkcs11Backend backend)
    {
        if (!backend.RequiresUserLogin)
            Assert.Skip("The backend has no login.");
        LowLevelPkcs11Library lowLevel = backend.Library.LowLevelLibrary!;
        LogOutTheToken(lowLevel, backend.SlotId);

        string label = $"kl-so-{Guid.NewGuid():N}";
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
        using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
        using var attrSession = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrPrivate = new ObjectAttribute(CKA.CKA_PRIVATE, true);

        using var so = Slot(backend).OpenSessionCore();
        var sid = (NativeCULong)so.SessionId;
        AssertRv(CKR.CKR_OK, lowLevel.C_Login(sid, CKU.CKU_SO, backend.SoPin.Span), "C_Login as the SO");
        try
        {
            var ex = Assert.ThrowsAny<Pkcs11Exception>(() => so.CreateObject([attrClass, attrSession, attrPrivate, attrLabel]));
            Assert.True(ex.ReturnValue == CKR.CKR_USER_NOT_LOGGED_IN, $"C_CreateObject of a private object as the SO returned {ex.ReturnValue}.");
        }
        finally { lowLevel.C_Logout(sid); }

        using var user = TestKeys.OpenLoggedInSession(backend);
        try { Assert.Empty(user.FindAllObjects([attrClass, attrLabel])); }
        finally { user.Logout(); }
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

    // A PIN shorter than ulMinPinLen or longer than ulMaxPinLen (§3.2, CK_TOKEN_INFO) logs nobody in, and C_SetPIN
    // will not set one: CKR_PIN_LEN_RANGE, "The specified PIN is too long or too short" (§5.1.6, §5.5.9), after
    // which the old PIN still logs in. C_Login may answer CKR_PIN_LEN_RANGE or CKR_PIN_INCORRECT: §5.1.6 says the
    // first "only applies to functions which attempt to set a PIN", yet C_Login of a PIN no token could hold is
    // refused for its length all the same, and §5.6.8 lists neither as wrong. No wrong PIN of a valid length is
    // ever presented, and every refusal is followed at once by a login with the right PIN, so no token is left a
    // try short; a token that counts the refusal and then refuses the right PIN fails here, and the rest of its
    // collection with it. A length of 0 is never tried (a NULL PIN means the protected authentication path,
    // §5.6.8), nor one above 1024 bytes. A C_SetPIN that does take the PIN is undone.
    internal static void Assert_PinOutsideTheLengthRange_IsRefused(IPkcs11Backend backend)
    {
        if (!backend.RequiresUserLogin)
            Assert.Skip("The backend has no login.");
        TokenInfo token = Slot(backend).GetTokenInfo();
        bool hasMin = token.MinPinLen != CK.CK_UNAVAILABLE_INFORMATION;
        bool hasMax = token.MaxPinLen != 0 && token.MaxPinLen != CK.CK_UNAVAILABLE_INFORMATION; // 0: CK_EFFECTIVELY_INFINITE
        ulong own = (ulong)backend.UserPin.Length;
        Assert.True((!hasMin || own >= token.MinPinLen) && (!hasMax || own <= token.MaxPinLen),
            $"The token's PIN length range [{token.MinPinLen}, {token.MaxPinLen}] leaves out the {own}-byte user PIN it was given.");
        var outside = new List<byte[]>();
        if (hasMin && token.MinPinLen >= 2)
            outside.Add([.. Enumerable.Repeat((byte)'7', (int)token.MinPinLen - 1)]);
        if (hasMax && token.MaxPinLen < 1024)
            outside.Add([.. Enumerable.Repeat((byte)'7', (int)token.MaxPinLen + 1)]);
        if (outside.Count == 0)
            Assert.Skip($"The token's PIN length range [{token.MinPinLen}, {token.MaxPinLen}] leaves no length to try.");

        LowLevelPkcs11Library lowLevel = backend.Library.LowLevelLibrary!;
        LogOutTheToken(lowLevel, backend.SlotId);
        NativeCULong session = OpenRawSession(lowLevel, backend.SlotId);
        try
        {
            foreach (byte[] pin in outside)
            {
                string what = $"a {pin.Length}-byte PIN (range [{token.MinPinLen}, {token.MaxPinLen}])";
                CKR rv = lowLevel.C_Login(session, CKU.CKU_USER, pin);
                Assert.True(rv is CKR.CKR_PIN_LEN_RANGE or CKR.CKR_PIN_INCORRECT, $"C_Login with {what} returned {rv}.");
                Assert.Equal(CKS.CKS_RW_PUBLIC_SESSION, (CKS)(ulong)SessionInfo(lowLevel, session).State);
                AssertRv(CKR.CKR_OK, lowLevel.C_Login(session, CKU.CKU_USER, backend.UserPin.Span), $"C_Login with the right PIN after {what}");

                rv = lowLevel.C_SetPIN(session, backend.UserPin.Span, pin);
                if (rv == CKR.CKR_OK)
                    AssertRv(CKR.CKR_OK, lowLevel.C_SetPIN(session, pin, backend.UserPin.Span), "C_SetPIN back to the right PIN");
                AssertRv(CKR.CKR_PIN_LEN_RANGE, rv, $"C_SetPIN to {what}");
                AssertRv(CKR.CKR_OK, lowLevel.C_Logout(session), "C_Logout");
                AssertRv(CKR.CKR_OK, lowLevel.C_Login(session, CKU.CKU_USER, backend.UserPin.Span), $"C_Login with the old PIN after C_SetPIN to {what}");
                AssertRv(CKR.CKR_OK, lowLevel.C_Logout(session), "C_Logout");
            }
        }
        finally
        {
            lowLevel.C_Logout(session);
            lowLevel.C_CloseSession(session);
        }
    }

    // === Access without a login ================================================

    // With nobody logged in, a session sees the token's public objects and none of its private ones (§4.4),
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

    // The AES key wraps, in order of preference; a 32-byte key needs no padding, so any of them does.
    private static readonly CKM[] AesKeyWraps = [CKM.CKM_AES_KEY_WRAP, CKM.CKM_AES_KEY_WRAP_KWP, CKM.CKM_AES_KEY_WRAP_PAD];

    public static TheoryData<string> PrivateObjectCreations =>
        ["CreateObject", "CopyObject", "GenerateKey", "GenerateKeyPair", "DeriveKey", "UnwrapKey", "EncapsulateKey", "DecapsulateKey"];

    // With nobody logged in, a call that would make a CKA_PRIVATE = TRUE object answers CKR_USER_NOT_LOGGED_IN
    // and makes nothing: "a private object cannot be created on a token unless the session attempting to create
    // it is logged in as the normal user" (§5.1.6, CKR_USER_NOT_LOGGED_IN; §4.4, CKA_PRIVATE). Every input the
    // call takes (a key to copy, a base key, an unwrapping key, a ciphertext) is a public session object made
    // while logged in, which the C_Logout leaves in place (§5.6.10 destroys only the private ones), so the
    // refusal can only be about the new object. CKA_PRIVATE is always given explicitly: its default is
    // token-specific (§4.4). Nothing carries the case's label after a new login.
    internal static void Assert_PrivateObjectCreation_WithoutALogin_IsUserNotLoggedIn(IPkcs11Backend backend, string call)
    {
        if (!backend.RequiresUserLogin)
            Assert.Skip("The backend has no login.");
        switch (call)
        {
            case "GenerateKey": backend.RequireMechanism(CKM.CKM_AES_KEY_GEN); break;
            case "GenerateKeyPair": backend.RequireMechanism(CKM.CKM_EC_KEY_PAIR_GEN); break;
            case "DeriveKey": backend.RequireMechanism(CKM.CKM_HKDF_DERIVE); break;
            case "UnwrapKey":
                backend.RequireMechanism(CKM.CKM_AES_KEY_GEN);
                if (!AesKeyWraps.Any(backend.Supports))
                    Assert.Skip($"Backend advertises none of {string.Join(", ", AesKeyWraps)}.");
                break;
            case "EncapsulateKey" or "DecapsulateKey":
                backend.RequireMechanisms(CKM.CKM_ML_KEM_KEY_PAIR_GEN, CKM.CKM_ML_KEM);
                backend.RequireMlKemParameterSet(1184); // ML-KEM-768
                break;
        }
        LowLevelPkcs11Library lowLevel = backend.Library.LowLevelLibrary!;
        LogOutTheToken(lowLevel, backend.SlotId);

        string label = $"kl-private-{Guid.NewGuid():N}";
        using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
        using var attrInput = new ObjectAttribute(CKA.CKA_LABEL, label + "-input");
        using var attrSession = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrPublic = new ObjectAttribute(CKA.CKA_PRIVATE, false);
        using var attrPrivate = new ObjectAttribute(CKA.CKA_PRIVATE, true);
        using var attrData = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
        using var attrSecret = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrAes = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
        using var attrGeneric = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
        using var attrLen32 = new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL);
        using var attrValue8 = new ObjectAttribute(CKA.CKA_VALUE, RandomNumberGenerator.GetBytes(8));
        using var attrValue32 = new ObjectAttribute(CKA.CKA_VALUE, RandomNumberGenerator.GetBytes(32));
        using var attrEncrypt = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
        using var attrSign = new ObjectAttribute(CKA.CKA_SIGN, true);
        using var attrVerify = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var attrDerive = new ObjectAttribute(CKA.CKA_DERIVE, true);
        using var attrWrap = new ObjectAttribute(CKA.CKA_WRAP, true);
        using var attrUnwrap = new ObjectAttribute(CKA.CKA_UNWRAP, true);
        using var attrExtractable = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
        using var attrEcParams = new ObjectAttribute(CKA.CKA_EC_PARAMS, TestKeys.EcP256Oid);
        using var attrMlKem768 = new ObjectAttribute(CKA.CKA_PARAMETER_SET, (ulong)CkpMlKem.CKP_ML_KEM_768);
        using var attrEncapsulate = new ObjectAttribute(CKA.CKA_ENCAPSULATE, true);
        using var attrDecapsulate = new ObjectAttribute(CKA.CKA_DECAPSULATE, true);

        using var session = Slot(backend).OpenSessionCore();
        using var pin = new SecurePin(backend.UserPin.Span);
        session.Login(CKU.CKU_USER, pin);
        bool loggedIn = true;
        try
        {
            // The inputs first, made while logged in; then the call, to run once nobody is.
            Action refused;
            switch (call)
            {
                case "CreateObject":
                    refused = () => session.CreateObject([attrData, attrSession, attrPrivate, attrLabel, attrValue8]);
                    break;
                case "CopyObject":
                    {
                        ObjectHandle source = session.CreateObject([attrData, attrSession, attrPublic, attrInput, attrValue8]);
                        refused = () => session.CopyObject(source, [attrPrivate, attrLabel]);
                        break;
                    }
                case "GenerateKey":
                    refused = () => session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN),
                        [attrSecret, attrAes, attrLen32, attrSession, attrPrivate, attrLabel, attrEncrypt]);
                    break;
                case "GenerateKeyPair":
                    // Only the private half asks to be private, so it is the only reason to refuse.
                    refused = () => session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN),
                        [attrSession, attrPublic, attrEcParams, attrVerify, attrLabel],
                        [attrSession, attrPrivate, attrSign, attrLabel], out _, out _);
                    break;
                case "DeriveKey":
                    {
                        ObjectHandle baseKey = session.CreateObject([attrSecret, attrGeneric, attrSession, attrPublic, attrDerive, attrInput, attrValue32]);
                        var mechanism = new Mechanism(CKM.CKM_HKDF_DERIVE,
                            CkmHkdfParams.WithoutSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256, "kl"u8));
                        refused = () => session.DeriveKey(mechanism, baseKey,
                            [attrSecret, attrGeneric, attrLen32, attrSession, attrPrivate, attrLabel, attrSign]);
                        break;
                    }
                case "UnwrapKey":
                    {
                        ObjectHandle kek = session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN),
                            [attrSecret, attrAes, attrLen32, attrSession, attrPublic, attrWrap, attrUnwrap, attrInput]);
                        ObjectHandle target = session.CreateObject([attrSecret, attrAes, attrSession, attrPublic, attrExtractable, attrEncrypt, attrInput, attrValue32]);
                        var wrap = new Mechanism(AesKeyWraps.First(backend.Supports));
                        byte[] wrapped = session.WrapKey(wrap, kek, target);
                        refused = () => session.UnwrapKey(wrap, kek, wrapped,
                            [attrSecret, attrAes, attrSession, attrPrivate, attrLabel, attrEncrypt]);
                        break;
                    }
                default: // EncapsulateKey, DecapsulateKey
                    {
                        session.GenerateKeyPair(new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN),
                            [attrSession, attrPublic, attrMlKem768, attrEncapsulate, attrInput],
                            [attrSession, attrPublic, attrDecapsulate, attrInput], out ObjectHandle publicKey, out ObjectHandle privateKey);
                        List<ObjectAttribute> template = [attrSecret, attrGeneric, attrSession, attrPrivate, attrLabel];
                        if (call == "EncapsulateKey")
                        {
                            refused = () => session.EncapsulateKey(new Mechanism(CKM.CKM_ML_KEM), publicKey, template, expectedCiphertextLen: 1088);
                            break;
                        }
                        using (var read = session.GetAttributeValue(privateKey, [CKA.CKA_PRIVATE]))
                        {
                            if (read[0].GetValueAsBool())
                                Assert.Skip("The token made the ML-KEM private key private though the template asked for a public one.");
                        }
                        (byte[] ciphertext, _) = session.EncapsulateKey(new Mechanism(CKM.CKM_ML_KEM), publicKey,
                            [attrSecret, attrGeneric, attrSession, attrPublic, attrInput], expectedCiphertextLen: 1088);
                        refused = () => session.DecapsulateKey(new Mechanism(CKM.CKM_ML_KEM), privateKey, ciphertext, template);
                        break;
                    }
            }

            session.Logout();
            loggedIn = false;
            Assert.Equal(CKS.CKS_RW_PUBLIC_SESSION, (CKS)(ulong)SessionInfo(lowLevel, (NativeCULong)session.SessionId).State);

            var ex = Assert.ThrowsAny<Pkcs11Exception>(refused);
            if (call == "CopyObject")
            {
                // §4.1.3: a token "might not actually support modification of" CKA_PRIVATE during a copy, and then
                // refuses the template instead, which creates nothing either.
                Assert.True(ex.ReturnValue is CKR.CKR_USER_NOT_LOGGED_IN or CKR.CKR_ATTRIBUTE_READ_ONLY or CKR.CKR_TEMPLATE_INCONSISTENT,
                    $"C_CopyObject to a private copy with nobody logged in returned {ex.ReturnValue}.");
            }
            else
            {
                Assert.True(ex.ReturnValue == CKR.CKR_USER_NOT_LOGGED_IN, $"{call} of a private object with nobody logged in returned {ex.ReturnValue}.");
            }

            session.Login(CKU.CKU_USER, pin);
            loggedIn = true;
            Assert.Empty(session.FindAllObjects([attrLabel]));
        }
        finally
        {
            if (loggedIn)
                session.Logout();
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

    public static TheoryData<string> ReadOnlySessionWrites =>
        ["GenerateKey", "GenerateKeyPair", "DeriveKey", "UnwrapKey", "CopyObject", "SetAttributeValue", "DestroyObject"];

    // A read-only session neither makes nor changes a token object, by any call: "Only session objects can be
    // created during a read-only session" (§5.7.1, §5.7.2 for a copy), modified (§5.7.6) or destroyed (§5.7.3),
    // and C_GenerateKey, C_GenerateKeyPair (either half), C_DeriveKey and C_UnwrapKey answer the same
    // CKR_SESSION_READ_ONLY (§5.1.6, §5.18). The same call on session objects succeeds. The user is logged in
    // (from a read/write session, where the token object is made); the inputs are session objects made in the
    // read-only session itself, so the module's session-object scope does not matter.
    internal static void Assert_ReadOnlySession_RefusesTokenObjectWrites(IPkcs11Backend backend, string call)
    {
        if (!backend.SupportsTokenObjects)
            Assert.Skip("The backend has no token objects.");
        switch (call)
        {
            case "GenerateKey": backend.RequireMechanism(CKM.CKM_AES_KEY_GEN); break;
            case "GenerateKeyPair": backend.RequireMechanism(CKM.CKM_EC_KEY_PAIR_GEN); break;
            case "DeriveKey":
                if (!backend.Supports(CKM.CKM_HKDF_DERIVE))
                    backend.RequireMechanisms(CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDH1_DERIVE);
                break;
            case "UnwrapKey":
                backend.RequireMechanism(CKM.CKM_AES_KEY_GEN);
                if (!AesKeyWraps.Any(backend.Supports))
                    Assert.Skip($"Backend advertises none of {string.Join(", ", AesKeyWraps)}.");
                break;
        }

        string label = $"kl-rowrite-{Guid.NewGuid():N}";
        using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
        using var attrRenamed = new ObjectAttribute(CKA.CKA_LABEL, label + "-renamed");
        using var attrOnToken = new ObjectAttribute(CKA.CKA_TOKEN, true);
        using var attrSession = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrData = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
        using var attrSecret = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrAes = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
        using var attrGeneric = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
        using var attrLen32 = new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL);
        using var attrValue32 = new ObjectAttribute(CKA.CKA_VALUE, RandomNumberGenerator.GetBytes(32));
        using var attrEncrypt = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
        using var attrSign = new ObjectAttribute(CKA.CKA_SIGN, true);
        using var attrVerify = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var attrDerive = new ObjectAttribute(CKA.CKA_DERIVE, true);
        using var attrWrap = new ObjectAttribute(CKA.CKA_WRAP, true);
        using var attrUnwrap = new ObjectAttribute(CKA.CKA_UNWRAP, true);
        using var attrExtractable = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
        using var attrEcParams = new ObjectAttribute(CKA.CKA_EC_PARAMS, TestKeys.EcP256Oid);

        using var rw = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle tokenObject = CreateTokenDataObject(rw, label, isPrivate: false);
            using var ro = Slot(backend).OpenSessionCore(readWrite: false);
            using var insecure = ro.UsePolicy(CryptoPolicy.AllowInsecure); // ECDH with CKD_NULL below
            ObjectHandle sessionObject = ro.CreateObject([attrData, attrSession, attrLabel]);

            // Each pair: the call on a token object, then the same call on a session object.
            (Action Token, Action Session)[] calls;
            switch (call)
            {
                case "GenerateKey":
                    {
                        var generate = new Mechanism(CKM.CKM_AES_KEY_GEN);
                        calls = [(() => ro.GenerateKey(generate, [attrSecret, attrAes, attrLen32, attrOnToken, attrEncrypt, attrLabel]),
                                  () => ro.GenerateKey(generate, [attrSecret, attrAes, attrLen32, attrSession, attrEncrypt, attrLabel]))];
                        break;
                    }
                case "GenerateKeyPair":
                    {
                        var generate = new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN);
                        void Pair(ObjectAttribute publicToken, ObjectAttribute privateToken) =>
                            ro.GenerateKeyPair(generate, [publicToken, attrEcParams, attrVerify, attrLabel], [privateToken, attrSign, attrLabel], out _, out _);
                        calls = [(() => Pair(attrOnToken, attrSession), () => Pair(attrSession, attrSession)),
                                 (() => Pair(attrSession, attrOnToken), () => Pair(attrSession, attrSession))];
                        break;
                    }
                case "DeriveKey":
                    {
                        Mechanism derive;
                        ObjectHandle baseKey;
                        if (backend.Supports(CKM.CKM_HKDF_DERIVE))
                        {
                            baseKey = ro.CreateObject([attrSecret, attrGeneric, attrSession, attrDerive, attrLabel, attrValue32]);
                            derive = new Mechanism(CKM.CKM_HKDF_DERIVE, CkmHkdfParams.WithoutSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256, "kl"u8));
                        }
                        else
                        {
                            ro.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), [attrSession, attrEcParams, attrLabel], [attrSession, attrDerive, attrLabel], out _, out baseKey);
                            ro.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), [attrSession, attrEcParams, attrLabel], [attrSession, attrDerive, attrLabel], out ObjectHandle peer, out _);
                            using var point = ro.GetAttributeValue(peer, [CKA.CKA_EC_POINT]);
                            derive = new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, point[0].GetValueAsByteArray()));
                        }
                        calls = [(() => ro.DeriveKey(derive, baseKey, [attrSecret, attrGeneric, attrLen32, attrOnToken, attrSign, attrLabel]),
                                  () => ro.DeriveKey(derive, baseKey, [attrSecret, attrGeneric, attrLen32, attrSession, attrSign, attrLabel]))];
                        break;
                    }
                case "UnwrapKey":
                    {
                        ObjectHandle kek = ro.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), [attrSecret, attrAes, attrLen32, attrSession, attrWrap, attrUnwrap, attrLabel]);
                        ObjectHandle target = ro.CreateObject([attrSecret, attrAes, attrSession, attrExtractable, attrEncrypt, attrLabel, attrValue32]);
                        var wrap = new Mechanism(AesKeyWraps.First(backend.Supports));
                        byte[] wrapped = ro.WrapKey(wrap, kek, target);
                        calls = [(() => ro.UnwrapKey(wrap, kek, wrapped, [attrSecret, attrAes, attrOnToken, attrEncrypt, attrLabel]),
                                  () => ro.UnwrapKey(wrap, kek, wrapped, [attrSecret, attrAes, attrSession, attrEncrypt, attrLabel]))];
                        break;
                    }
                case "CopyObject":
                    calls = [(() => ro.CopyObject(tokenObject, [attrLabel]), () => ro.CopyObject(sessionObject, [attrLabel])),
                             (() => ro.CopyObject(sessionObject, [attrOnToken, attrLabel]), () => ro.CopyObject(sessionObject, [attrLabel]))];
                    break;
                case "SetAttributeValue":
                    calls = [(() => ro.SetAttributeValue(tokenObject, [attrRenamed]), () => ro.SetAttributeValue(sessionObject, [attrRenamed]))];
                    break;
                default: // DestroyObject
                    calls = [(() => ro.DestroyObject(tokenObject), () => ro.DestroyObject(sessionObject))];
                    break;
            }

            for (int i = 0; i < calls.Length; i++)
            {
                Exception? ex = Record.Exception(calls[i].Token);
                Assert.True(ex is Pkcs11Exception { ReturnValue: CKR.CKR_SESSION_READ_ONLY },
                    $"{call} #{i + 1} of a token object in a read-only session gave {(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name ?? "CKR_OK"}.");
                calls[i].Session();
            }

            // The token object is still the only one, under its own label. Told by CKA_TOKEN rather than by the
            // search template, and the read/write session sees no other session's session objects anyway.
            Assert.Equal([tokenObject.ObjectId], TokenObjectsLabelled(rw, attrLabel, attrRenamed).Select(h => h.ObjectId));
            using var read = rw.GetAttributeValue(tokenObject, [CKA.CKA_LABEL]);
            Assert.Equal(label, read[0].GetValueAsString());
        }
        finally
        {
            foreach (ObjectHandle handle in TokenObjectsLabelled(rw, attrLabel, attrRenamed))
                rw.DestroyObject(handle);
            TestKeys.LogoutIfRequired(backend, rw);
        }
    }

    private static List<ObjectHandle> TokenObjectsLabelled(Pkcs11SessionCore session, params ObjectAttribute[] labels)
    {
        var found = new List<ObjectHandle>();
        foreach (ObjectAttribute label in labels)
        {
            foreach (ObjectHandle handle in session.FindAllObjects([label]))
            {
                using var read = session.GetAttributeValue(handle, [CKA.CKA_TOKEN]);
                if (read[0].GetValueAsBool())
                    found.Add(handle);
            }
        }
        return found;
    }

    // === Logout ================================================================

    // C_Logout invalidates the application's handles to private objects and destroys its private session objects
    // (§5.6.10). With nobody logged in, the handle of a private token key is CKR_OBJECT_HANDLE_INVALID to
    // C_GetAttributeValue, and C_EncryptInit refuses it; a private session object is found by no search and its
    // handle stays CKR_OBJECT_HANDLE_INVALID after a new login. A public session object keeps its handle
    // throughout. The token key's old handle is not checked after the new login: a module may give the key the
    // same number again, and a search then finds it under that number.
    // C_EncryptInit may answer CKR_KEY_HANDLE_INVALID or CKR_USER_NOT_LOGGED_IN, the two §5.8.1 lists for it, or
    // CKR_OBJECT_HANDLE_INVALID: the handle is an object handle §5.6.10 made invalid, and the spec says no more
    // about which of the two handle codes a key handle gets then.
    // tokenKeyEncryptInit records a backend's own answer to C_EncryptInit (null: the ones above).
    internal static void Assert_Logout_InvalidatesPrivateHandles(IPkcs11Backend backend, CKR? tokenKeyEncryptInit = null)
    {
        if (!backend.RequiresUserLogin)
            Assert.Skip("The backend has no login.");
        LowLevelPkcs11Library lowLevel = backend.Library.LowLevelLibrary!;
        LogOutTheToken(lowLevel, backend.SlotId);

        string label = $"kl-logout-{Guid.NewGuid():N}";
        using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
        using var attrSecret = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrAes = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
        using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, RandomNumberGenerator.GetBytes(32));
        using var attrEncrypt = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
        using var attrOnToken = new ObjectAttribute(CKA.CKA_TOKEN, true);
        using var attrSession = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrPrivate = new ObjectAttribute(CKA.CKA_PRIVATE, true);
        using var attrPublic = new ObjectAttribute(CKA.CKA_PRIVATE, false);
        using var attrData = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);

        using var session = Slot(backend).OpenSessionCore();
        var sid = (NativeCULong)session.SessionId;
        using var pin = new SecurePin(backend.UserPin.Span);
        session.Login(CKU.CKU_USER, pin);
        bool loggedIn = true;
        try
        {
            ObjectHandle? tokenKey = backend.SupportsTokenObjects
                ? session.CreateObject([attrSecret, attrAes, attrOnToken, attrPrivate, attrEncrypt, attrLabel, attrValue])
                : null;
            ObjectHandle privateSessionObject = session.CreateObject([attrData, attrSession, attrPrivate, attrLabel]);
            ObjectHandle publicSessionObject = session.CreateObject([attrData, attrSession, attrPublic, attrLabel]);

            session.Logout();
            loggedIn = false;

            if (tokenKey is { } key)
            {
                AssertRv(CKR.CKR_OBJECT_HANDLE_INVALID, ClassOf(lowLevel, sid, key), "C_GetAttributeValue on a private token key after C_Logout");
                if (backend.Supports(CKM.CKM_AES_ECB))
                {
                    // ECB only because it takes no parameter; an operation it starts is ended at once.
                    var ecb = new CK_MECHANISM { Mechanism = (NativeCULong)(ulong)CKM.CKM_AES_ECB };
                    CKR rv = lowLevel.C_EncryptInit(sid, in ecb, (NativeCULong)key.ObjectId);
                    if (rv == CKR.CKR_OK)
                        lowLevel.C_EncryptFinal(sid, [], lengthOnly: false, out _);
                    if (tokenKeyEncryptInit is { } expected)
                        AssertRv(expected, rv, "C_EncryptInit with a private token key after C_Logout");
                    else
                        Assert.True(rv is CKR.CKR_KEY_HANDLE_INVALID or CKR.CKR_USER_NOT_LOGGED_IN or CKR.CKR_OBJECT_HANDLE_INVALID,
                            $"C_EncryptInit with a private token key after C_Logout returned {rv}.");
                }
            }
            AssertRv(CKR.CKR_OBJECT_HANDLE_INVALID, ClassOf(lowLevel, sid, privateSessionObject), "C_GetAttributeValue on a private session object after C_Logout");
            AssertRv(CKR.CKR_OK, ClassOf(lowLevel, sid, publicSessionObject), "C_GetAttributeValue on a public session object after C_Logout");
            Assert.Equal([publicSessionObject.ObjectId], session.FindAllObjects([attrLabel]).Select(h => h.ObjectId));

            session.Login(CKU.CKU_USER, pin);
            loggedIn = true;
            AssertRv(CKR.CKR_OBJECT_HANDLE_INVALID, ClassOf(lowLevel, sid, privateSessionObject), "C_GetAttributeValue on a destroyed private session object after a new login");
            Assert.DoesNotContain(session.FindAllObjects([attrData, attrLabel]), h => h.ObjectId != publicSessionObject.ObjectId);
        }
        finally
        {
            if (!loggedIn)
                session.Login(CKU.CKU_USER, pin);
            // Found again by label: the token key's handle may have changed with the new login.
            foreach (ObjectHandle handle in session.FindAllObjects([attrLabel]))
                session.DestroyObject(handle);
            session.Logout();
        }
    }

    // C_GetAttributeValue of CKA_CLASS, its length only, for the module's own answer about the handle.
    private static CKR ClassOf(LowLevelPkcs11Library lowLevel, NativeCULong session, ObjectHandle handle)
    {
        CK_ATTRIBUTE[] template = [new CK_ATTRIBUTE { type = (NativeCULong)(ulong)CKA.CKA_CLASS }];
        return lowLevel.C_GetAttributeValue(session, (NativeCULong)handle.ObjectId, template);
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

    // A session object belongs to the application, not to the session that made it (§5.6.2): another session
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
