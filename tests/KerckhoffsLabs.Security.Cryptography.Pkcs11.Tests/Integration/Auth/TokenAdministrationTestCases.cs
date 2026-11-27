using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>
/// Token administration on real modules: a logout on one token while another stays logged in, a token initialized
/// again in the same process, and C_SetPIN raced across threads. After pkcs11-check's token administration probes
/// (https://github.com/mingulov/pkcs11-check, src/pkcs11_check/testcases/_probes/token_admin.py, 0.3.1: QC9b
/// cross-token logout, QC11a same-process reinitialization, QC11c concurrent PIN change).
/// </summary>
/// <remarks>
/// <para>
/// Every case works on the fixture's scratch slot (<see cref="IPkcs11Backend.ScratchSlotId"/>), never on the
/// fixture's own token, which the other cases share: each initializes the scratch token afresh with
/// <c>C_InitToken</c> and sets its user PIN, so it may log the token out, spend PIN retries and change its PIN
/// freely. A fixture without a scratch slot skips them.
/// </para>
/// <para>
/// The fixture's token is only logged in to and used (the control of the cross-token case), with its own PIN.
/// </para>
/// </remarks>
internal static class TokenAdministrationTestCases
{
    private static readonly byte[] Digest = SHA256.HashData("token administration"u8);

    // The scratch token's PINs (Settings.ScratchSoPin is the SO's): letters, digits and a hyphen, which every
    // backend's PIN rules take (Craton HSM's want two character classes and three distinct bytes).
    private static ReadOnlySpan<byte> ScratchSoPin => Encoding.ASCII.GetBytes(Settings.ScratchSoPin);
    private static ReadOnlySpan<byte> ScratchUserPin => "kl-user-2468"u8;

    // The PINs the concurrent C_SetPIN cases race to, one per thread (as pkcs11-check's _QC11C_RACE_PINS).
    private static readonly byte[][] RacePins =
        [.. new[] { "kl-race-1", "kl-race-2", "kl-race-3", "kl-race-4" }.Select(Encoding.ASCII.GetBytes)];

    private static Pkcs11Slot MainSlot(IPkcs11Backend backend)
        => backend.Library.GetSlotList().First(s => (NativeCULong)s.SlotId.Value == backend.SlotId);

    private static Pkcs11Slot ScratchSlot(IPkcs11Backend backend)
    {
        if (backend.ScratchSlotId is null)
            Assert.Skip("The fixture has no scratch slot: its module offers one token only.");
        NativeCULong id = backend.ScratchSlotId.Value;
        return backend.Library.GetSlotList(tokenPresent: false).FirstOrDefault(s => (NativeCULong)s.SlotId.Value == id)
            ?? throw new InvalidOperationException($"The scratch slot {(ulong)id} is not in the slot list.");
    }

    // Initializes the scratch token afresh (C_InitToken), then sets its user PIN as the SO (C_InitPIN). Whatever the
    // token held before, a factory-state token with a user PIN of userPin; the label is new each time.
    private static Pkcs11Slot ProvisionScratch(IPkcs11Backend backend, string label, ReadOnlySpan<byte> userPin)
    {
        Pkcs11Slot slot = ScratchSlot(backend);
        using (var soPin = new SecurePin(ScratchSoPin))
            slot.InitTokenWithPin(soPin, label);
        using (var soPin = new SecurePin(ScratchSoPin))
        using (Pkcs11Login so = slot.Login(TokenUser.SecurityOfficer, soPin))
        using (var pin = new SecurePin(userPin))
            so.InitUserPinWithPin(pin);
        return slot;
    }

    private static string NewLabel(string what) => $"kl-{what}-{Guid.NewGuid():N}"[..24];

    private static Pkcs11Login LogIn(Pkcs11Slot slot, ReadOnlySpan<byte> pin)
    {
        using var securePin = new SecurePin(pin);
        return slot.Login(TokenUser.User, securePin);
    }

    // A private session data object: what C_Logout destroys (PKCS#11 v3.2 §5.6.4).
    private static Pkcs11Object CreatePrivateWitness(Pkcs11Session session, string label, byte[] value)
    {
        using var template = ObjectTemplate.ForData().Label(label).Value(value)
            .OnToken(false).Attribute(CKA.CKA_PRIVATE, true).Build();
        return session.CreateObject(template);
    }

    private static int CountLabelled(Pkcs11Session session, string label)
    {
        using var filter = ObjectTemplate.ForData().Label(label).Build();
        using var found = session.FindObjects(filter);
        return found.Count;
    }

    // === Logout on one token, another logged in ====================================================================

    /// <summary>
    /// A logout ends the login of one token, not the application's logins: PKCS#11 v3.2 §5.6 makes a login the
    /// application's and the token's, and §5.6.4 has <c>C_Logout</c> destroy the private session objects "from
    /// sessions belonging to the application" on that token. With the scratch token (target) and the fixture's
    /// (control) both logged in, each holding a private session object, ending the target's login leaves the
    /// control's in "R/W User Functions": its object is still found and read, and its private key still signs,
    /// with no new login. The target's session, which stays open, finds its object no more, and the module
    /// refuses the object's handle without writing a byte into the read buffer.
    /// </summary>
    /// <param name="backend">The backend.</param>
    /// <param name="destroysPrivateSessionObjects">
    /// <see langword="false"/> on a module whose <c>C_Logout</c> leaves private session objects (a gap the backend's
    /// quirk tests track): the target's side is then not asserted.
    /// </param>
    internal static void Assert_LogoutOfOneToken_LeavesTheOtherLoggedIn(IPkcs11Backend backend, bool destroysPrivateSessionObjects = true)
    {
        if (!backend.RequiresUserLogin)
            Assert.Skip("The backend's token has no login.");
        backend.RequireMechanisms(CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA);
        Pkcs11Slot target = ProvisionScratch(backend, NewLabel("target"), ScratchUserPin);
        Pkcs11Slot control = MainSlot(backend);
        byte[] value = RandomNumberGenerator.GetBytes(16);
        string targetLabel = NewLabel("target-w");
        string controlLabel = NewLabel("control-w");

        // A slot session holds no login: it stays open through the target's logout and observes it.
        using Pkcs11Session observer = target.OpenSession(SessionAccess.ReadWrite);
        using Pkcs11Login controlLogin = LogIn(control, backend.UserPin.Span);
        using Pkcs11Session controlSession = controlLogin.OpenSession();
        using Pkcs11Key controlKey = controlSession.GenerateEcSigningKeyPair(label: NewLabel("control-k"), persistOnToken: false);
        using Pkcs11Object controlWitness = CreatePrivateWitness(controlSession, controlLabel, value);

        ulong targetHandle;
        using (Pkcs11Login targetLogin = LogIn(target, ScratchUserPin))
        {
            Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, observer.GetSessionInfo().State);
            using Pkcs11Object targetWitness = CreatePrivateWitness(observer, targetLabel, value);
            targetHandle = targetWitness.Handle.ObjectId;
            Assert.Equal(value, targetWitness.GetValue());
            Assert.Equal(1, CountLabelled(observer, targetLabel));
        } // the target's last holder: C_Logout

        Assert.Equal(CKS.CKS_RW_PUBLIC_SESSION, observer.GetSessionInfo().State);

        // The control's login is untouched: same state, same object, same key, and no login sent.
        Assert.True(controlLogin.IsActive);
        Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, controlSession.GetSessionInfo().State);
        Assert.Equal(1, CountLabelled(controlSession, controlLabel));
        Assert.Equal(value, controlWitness.GetValue());
        var ecdsa = new Mechanism(CKM.CKM_ECDSA);
        Assert.True(controlKey.Verify(ecdsa, Digest, controlKey.Sign(ecdsa, Digest)));

        if (!destroysPrivateSessionObjects)
            return;
        Assert.Equal(0, CountLabelled(observer, targetLabel));
        // The handle read through the raw dispatch: the library would refuse it itself (the login it was made under
        // has ended). A buffer of a known pattern shows whether the module wrote any of the object's bytes.
        LowLevelPkcs11Library lowLevel = backend.Library.LowLevelLibrary!;
        byte[] poison = [.. Enumerable.Repeat(new byte[] { 0xA5, 0x5A }, 32).SelectMany(b => b)];
        byte[] buffer = [.. poison];
        CKR rv = ReadValue(lowLevel, (NativeCULong)observer.Core.SessionId, (NativeCULong)targetHandle, buffer);
        Assert.True(rv != CKR.CKR_OK, "The private session object's handle still reads after C_Logout.");
        Assert.True(buffer.AsSpan().SequenceEqual(poison), $"C_GetAttributeValue refused the handle ({rv}) but wrote into the buffer.");
    }

    private static unsafe CKR ReadValue(LowLevelPkcs11Library lowLevel, NativeCULong session, NativeCULong handle, byte[] buffer)
    {
        fixed (byte* p = buffer)
        {
            var attribute = new CK_ATTRIBUTE { type = (NativeCULong)(ulong)CKA.CKA_VALUE, value = (IntPtr)p, valueLen = (NativeCULong)(ulong)buffer.Length };
            return lowLevel.C_GetAttributeValue(session, handle, [attribute]);
        }
    }

    // === The same token initialized again =========================================================================

    /// <summary>
    /// <c>C_InitToken</c> on a token this process has used returns it to its factory state (PKCS#11 v3.2 §5.5.4): its
    /// objects are gone, its label is the new one, and its user PIN is not initialized; and nothing the library learnt
    /// about the token before stays. A user PIN the token refused before (which the library refuses itself from then
    /// on) is the new token's user PIN once the SO sets it, and logs in; the token's old user PIN is refused by the
    /// module, not by the library.
    /// </summary>
    internal static void Assert_ReinitializedToken_KeepsNothingFromBefore(IPkcs11Backend backend)
    {
        if (!backend.RequiresUserLogin)
            Assert.Skip("The backend's token has no login.");
        string firstLabel = NewLabel("reinit-1");
        Pkcs11Slot slot = ProvisionScratch(backend, firstLabel, ScratchUserPin);
        string objectLabel = NewLabel("reinit-o");
        byte[] refusedBefore = [.. RacePins[0]];

        using (Pkcs11Login login = LogIn(slot, ScratchUserPin))
        using (Pkcs11Session session = login.OpenSession())
        {
            // Public, so a public session would still find it if C_InitToken had left it.
            using var template = ObjectTemplate.ForData().Label(objectLabel).Value("before"u8)
                .OnToken(backend.SupportsTokenObjects).Attribute(CKA.CKA_PRIVATE, false).Build();
            using Pkcs11Object created = session.CreateObject(template);
            Assert.Equal(1, CountLabelled(session, objectLabel));
        }

        // A wrong PIN, refused by the module and then remembered by the library.
        slot.ForgetRefusedPins();
        Assert.ThrowsAny<Pkcs11AuthenticationException>(() => LogIn(slot, refusedBefore).Dispose());
        var remembered = Assert.ThrowsAny<Pkcs11AuthenticationException>(() => LogIn(slot, refusedBefore).Dispose());
        Assert.Contains("refused this PIN before", remembered.Message, StringComparison.Ordinal);

        string secondLabel = NewLabel("reinit-2");
        using (var soPin = new SecurePin(ScratchSoPin))
            slot.InitTokenWithPin(soPin, secondLabel);

        TokenInfo info = slot.GetTokenInfo();
        Assert.Equal(secondLabel, info.Label);
        Assert.True(info.TokenFlags.TokenInitialized);
        Assert.False(info.TokenFlags.UserPinInitialized, "C_InitToken left the user PIN initialized.");
        using (Pkcs11Session publicSession = slot.OpenSession(SessionAccess.ReadOnly))
            Assert.Equal(0, CountLabelled(publicSession, objectLabel));

        using (var soPin = new SecurePin(ScratchSoPin))
        using (Pkcs11Login so = slot.Login(TokenUser.SecurityOfficer, soPin))
        using (var pin = new SecurePin(refusedBefore))
            so.InitUserPinWithPin(pin);

        using (Pkcs11Login login = LogIn(slot, refusedBefore))
        using (Pkcs11Session session = login.OpenSession())
        {
            Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, session.GetSessionInfo().State);
            Assert.Equal(0, CountLabelled(session, objectLabel));
        }

        var stale = Assert.ThrowsAny<Pkcs11AuthenticationException>(() => LogIn(slot, ScratchUserPin).Dispose());
        Assert.DoesNotContain("refused this PIN before", stale.Message, StringComparison.Ordinal);
        slot.ForgetRefusedPins();
    }

    // === C_SetPIN raced across threads ============================================================================

    /// <summary>
    /// Four sessions of one login change the user PIN from the same old PIN to four different new ones at once, through
    /// the library. The library sends one PIN to a slot at a time, so the token sees the changes in turn: the first
    /// takes, the second is refused (<c>CKR_PIN_INCORRECT</c>, the old PIN being stale), and the library refuses the
    /// last two itself, without sending the stale PIN again. Exactly one change succeeds, no thread hangs, and the
    /// winner's PIN is the one that logs in.
    /// </summary>
    internal static void Assert_ConcurrentSetPin_ThroughTheLibrary_OneWins(IPkcs11Backend backend)
    {
        if (!backend.RequiresUserLogin)
            Assert.Skip("The backend's token has no login.");
        Pkcs11Slot slot = ProvisionScratch(backend, NewLabel("setpin"), ScratchUserPin);
        slot.ForgetRefusedPins();
        var outcomes = new Exception?[RacePins.Length];
        var succeeded = new bool[RacePins.Length];
        try
        {
            using (Pkcs11Login login = LogIn(slot, ScratchUserPin))
            {
                Pkcs11Session[] sessions = [.. RacePins.Select(_ => login.OpenSession())];
                try
                {
                    using var barrier = new Barrier(RacePins.Length);
                    Task[] racers = [.. Enumerable.Range(0, RacePins.Length).Select(i => Task.Factory.StartNew(() =>
                    {
                        using var oldPin = new SecurePin(ScratchUserPin);
                        using var newPin = new SecurePin(RacePins[i]);
                        barrier.SignalAndWait(TimeSpan.FromSeconds(30));
                        try
                        {
                            sessions[i].SetPinWithPin(oldPin, newPin);
                            succeeded[i] = true;
                        }
                        catch (Pkcs11Exception ex)
                        {
                            outcomes[i] = ex;
                        }
                    }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default))];
                    Assert.True(Task.WaitAll(racers, TimeSpan.FromSeconds(60)), "A C_SetPIN race did not finish: a thread hangs.");
                }
                finally
                {
                    foreach (Pkcs11Session session in sessions)
                        session.Dispose();
                }
            }

            int winner = Assert.Single(Enumerable.Range(0, RacePins.Length), i => succeeded[i]);
            Exception[] losers = [.. outcomes.Where(o => o is not null).Select(o => o!)];
            Assert.Equal(RacePins.Length - 1, losers.Length);
            Assert.All(losers, l => Assert.Equal(CKR.CKR_PIN_INCORRECT, Assert.IsAssignableFrom<Pkcs11AuthenticationException>(l).ReturnValue));
            // The stale PIN reached the token once: every other loser was refused by the library.
            Assert.Single(losers, l => !l.Message.Contains("refused this old PIN before", StringComparison.Ordinal));

            using Pkcs11Login won = LogIn(slot, RacePins[winner]);
            Assert.True(won.IsActive);
        }
        finally
        {
            slot.ForgetRefusedPins();
        }
    }

    /// <summary>
    /// The same race straight at the module, through the raw dispatch (as pkcs11-check's QC11c sends it): four sessions,
    /// logged in, call <c>C_SetPIN</c> from the old PIN at once. PKCS#11 v3.2 §5.4 has a module initialized with
    /// <c>CKF_OS_LOCKING_OK</c> (as the library initializes it) safe to call from several threads, so the outcome must
    /// be one of the orders the calls could have run in: at most one change takes, the rest refused, and exactly one of
    /// the PINs then logs in, the winner's (or the old PIN, when none took). Each login is tried once, winners first,
    /// so a token that keeps its retry count locks no PIN before the right one is tried. A refusal may be
    /// <c>CKR_PIN_LOCKED</c> as well as <c>CKR_PIN_INCORRECT</c>: Craton HSM rate-limits PIN attempts, and answers
    /// so within the backoff window that follows a wrong one (up to 5 s), where a login is tried again.
    /// </summary>
    internal static void Assert_ConcurrentSetPin_AtTheModule_Linearizes(IPkcs11Backend backend)
    {
        if (!backend.RequiresUserLogin)
            Assert.Skip("The backend's token has no login.");
        Pkcs11Slot slot = ProvisionScratch(backend, NewLabel("setpin-raw"), ScratchUserPin);
        LowLevelPkcs11Library lowLevel = backend.Library.LowLevelLibrary!;
        var slotId = (NativeCULong)slot.SlotId.Value;
        byte[] oldPin = ScratchUserPin.ToArray();
        var answers = new CKR?[RacePins.Length];

        using var barrier = new Barrier(RacePins.Length);
        Task[] racers = [.. Enumerable.Range(0, RacePins.Length).Select(i => Task.Factory.StartNew(() =>
        {
            NativeCULong session = OpenRawSession(lowLevel, slotId);
            try
            {
                CKR login = lowLevel.C_Login(session, CKU.CKU_USER, oldPin);
                Assert.True(login is CKR.CKR_OK or CKR.CKR_USER_ALREADY_LOGGED_IN, $"C_Login returned {login}.");
                barrier.SignalAndWait(TimeSpan.FromSeconds(30));
                answers[i] = lowLevel.C_SetPIN(session, oldPin, RacePins[i]);
            }
            finally
            {
                lowLevel.C_CloseSession(session); // the last one closed logs the token out (§5.6.3)
            }
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default))];
        Assert.True(Task.WaitAll(racers, TimeSpan.FromSeconds(60)), "A raw C_SetPIN race did not finish: a thread hangs.");

        int[] winners = [.. Enumerable.Range(0, RacePins.Length).Where(i => answers[i] == CKR.CKR_OK)];
        Assert.True(winners.Length <= 1,
            $"{winners.Length} C_SetPIN calls from the same old PIN all succeeded: answers {string.Join(", ", answers)}.");
        Assert.All(answers, a => Assert.True(a is CKR.CKR_OK or CKR.CKR_PIN_INCORRECT or CKR.CKR_PIN_LOCKED, $"C_SetPIN returned {a}."));

        // The candidates in pkcs11-check's order: the winners, then the old PIN, then the losers' new PINs.
        IEnumerable<byte[]> candidates = winners.Select(i => RacePins[i]).Append(oldPin)
            .Concat(Enumerable.Range(0, RacePins.Length).Where(i => !winners.Contains(i)).Select(i => RacePins[i]));
        var loggedIn = new List<string>();
        foreach (byte[] candidate in candidates)
        {
            NativeCULong session = OpenRawSession(lowLevel, slotId);
            try
            {
                CKR rv = LogInPastABackoff(lowLevel, session, candidate);
                if (rv == CKR.CKR_OK)
                {
                    loggedIn.Add(Encoding.ASCII.GetString(candidate));
                    lowLevel.C_Logout(session);
                    break; // a PIN that works ends the search: the rest would only spend retries
                }
                Assert.True(rv == CKR.CKR_PIN_INCORRECT, $"C_Login with a candidate PIN returned {rv}.");
            }
            finally
            {
                lowLevel.C_CloseSession(session);
            }
        }

        string expected = winners.Length == 1 ? Encoding.ASCII.GetString(RacePins[winners[0]]) : Encoding.ASCII.GetString(oldPin);
        Assert.Equal([expected], loggedIn);
    }

    // C_Login, tried again while the module answers CKR_PIN_LOCKED for at most the 5 s a rate-limiting module (Craton
    // HSM) backs off for after a wrong PIN; a PIN locked for good still answers CKR_PIN_LOCKED then.
    private static CKR LogInPastABackoff(LowLevelPkcs11Library lowLevel, NativeCULong session, byte[] pin)
    {
        DateTime giveUp = DateTime.UtcNow + TimeSpan.FromSeconds(6);
        while (true)
        {
            CKR rv = lowLevel.C_Login(session, CKU.CKU_USER, pin);
            if (rv != CKR.CKR_PIN_LOCKED || DateTime.UtcNow > giveUp)
                return rv;
            Thread.Sleep(250);
        }
    }

    private static NativeCULong OpenRawSession(LowLevelPkcs11Library lowLevel, NativeCULong slot)
    {
        CKR rv = lowLevel.C_OpenSession(slot, (NativeCULong)(CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), out NativeCULong session);
        Assert.True(rv == CKR.CKR_OK, $"C_OpenSession returned {rv}.");
        return session;
    }
}
