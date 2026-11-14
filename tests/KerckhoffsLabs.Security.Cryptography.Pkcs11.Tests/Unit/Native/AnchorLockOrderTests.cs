using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// The lock order on the anchor session of a token login (<see cref="TokenLoginRecord"/>): a core on the anchor's
/// side takes the gate before the anchor's lock, and the record's own sends on the anchor wait their turn for that
/// lock instead of refusing a thread that holds it. An ordinary session still refuses concurrent use.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class AnchorLockOrderTests : IDisposable
{
    private const string AlwaysAuthenticateEc = "aa-ec";

    // Every wait is bounded: a lock-order regression shows as a timed-out wait, not a hung run.
    private static readonly TimeSpan Bounded = TimeSpan.FromSeconds(5);

    // How long a thread that should be blocked is watched for not having returned.
    private static readonly TimeSpan Watch = TimeSpan.FromMilliseconds(200);

    private readonly LoginTokenModule _module = new();
    private readonly Pkcs11Library _library;
    private readonly SecurePin _pin;

    public AnchorLockOrderTests()
    {
        _module.AddObject(CKO.CKO_PRIVATE_KEY, AlwaysAuthenticateEc, isPrivate: true, keyType: CKK.CKK_EC,
            more: new Dictionary<CKA, byte[]> { [CKA.CKA_ALWAYS_AUTHENTICATE] = [1] });
        _library = _module.Load();
        _pin = new SecurePin(_module.ExpectedPin);
    }

    public void Dispose()
    {
        _pin.Dispose();
        _library.Dispose();
        _module.Dispose();
    }

    private Pkcs11Slot Slot => Assert.Single(_library.GetSlotList());

    private TokenLoginRecord Record => TokenLoginRegistry.Of(_library.LowLevelLibrary!.Module).For((NativeCULong)LoginTokenModule.SlotId);

    // Holds a session's lease on a thread of its own until released; returns once the lease is held.
    private static Thread HoldLease(Pkcs11SessionCore core, ManualResetEventSlim held, ManualResetEventSlim release)
    {
        var holder = new Thread(() =>
        {
            using (core.AcquireExclusive())
            {
                held.Set();
                release.Wait(Bounded);
            }
        })
        { IsBackground = true };
        holder.Start();
        Assert.True(held.Wait(Bounded, TestContext.Current.CancellationToken), "the lease was never taken");
        return holder;
    }

    [Fact]
    public void ShareLogin_WhileAnchorLeasedOnAnotherThread_WaitsInsteadOfThrowing()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        Pkcs11SessionCore anchor = Assert.IsType<Pkcs11SessionCore>(Record.Anchor);
        Assert.True(anchor.IsAnchorSide);
        using var held = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        Thread holder = HoldLease(anchor, held, release);

        Pkcs11Login? second = null;
        BackgroundWork sharing = BackgroundWork.Run(() => second = Slot.Login(TokenUser.User, _pin));
        try
        {
            // The share's C_Login waits for the anchor: it neither reaches the module nor returns.
            Assert.False(SpinWait.SpinUntil(() => _module.LoginCalls != 1 || !sharing.IsAlive, Watch),
                $"the share did not wait for the anchor: {sharing.Failure}");
        }
        finally
        {
            release.Set();
            Assert.True(holder.Join(Bounded), "the anchor's holder did not finish");
            Assert.True(sharing.Join(Bounded), "the share did not finish after the anchor was released");
        }

        Assert.Null(sharing.Failure);
        using Pkcs11Login shared = Assert.IsType<Pkcs11Login>(second);
        Assert.True(shared.IsActive);
        Assert.Equal(2, _module.LoginCalls);
    }

    [Fact]
    public void InitUserPin_WhileAnchorLeasedOnAnotherThread_Waits()
    {
        using Pkcs11Login so = Slot.Login(TokenUser.SecurityOfficer, _pin);
        Pkcs11SessionCore anchor = Assert.IsType<Pkcs11SessionCore>(Record.Anchor);
        using var held = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        Thread holder = HoldLease(anchor, held, release);

        using var userPin = new SecurePin("5678");
        BackgroundWork initializing = BackgroundWork.Run(() => so.InitUserPinWithPin(userPin));
        try
        {
            Assert.False(SpinWait.SpinUntil(() => _module.LastInitPin is not null || !initializing.IsAlive, Watch),
                $"C_InitPIN did not wait for the anchor: {initializing.Failure}");
        }
        finally
        {
            release.Set();
            Assert.True(holder.Join(Bounded), "the anchor's holder did not finish");
            Assert.True(initializing.Join(Bounded), "C_InitPIN did not finish after the anchor was released");
        }

        Assert.Null(initializing.Failure);
        Assert.Equal("5678"u8.ToArray(), _module.LastInitPin?.Pin);
    }

    // Review Focus 1. T1, inside an operation on a slot session (the gate shared), ends the login from its context
    // login (CKR_PIN_LOCKED), which closes the anchor and so waits for the anchor's lock. W, the final logout, is
    // queued on the gate. T2 asks for the anchor's lease. Taking the anchor's lock before the gate, T2 would hold the
    // lock while queued behind W, W would wait for T1, and T1 for T2's lock. Taking the gate first, T2 queues holding
    // nothing, T1 closes the anchor, and W finds the login already ended: no C_Logout.
    [Fact]
    public void EndLogin_FromAnotherSessionsOperation_WhileAnchorLeased_AndLogoutQueued_Completes()
    {
        _module.LockAfter = 1;
        Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        TokenLoginRecord record = Record;
        Pkcs11SessionCore anchor = Assert.IsType<Pkcs11SessionCore>(record.Anchor);
        using Pkcs11Session slotSession = Slot.OpenSession();
        slotSession.ContextAuthentication = ContextAuthentication.FromPin(_ => new SecurePin("9999"));
        using Pkcs11Key key = slotSession.OpenKey(AlwaysAuthenticateEc);
        ulong slotSessionId = slotSession.Core.SessionId;

        using var inContextLogin = new ManualResetEventSlim();
        using var proceed = new ManualResetEventSlim();
        _module.DuringLogin = session =>
        {
            if ((ulong)session != slotSessionId)
                return;
            inContextLogin.Set();
            proceed.Wait(Bounded);
        };

        var t1 = new BackgroundWork(() => key.Sign(new Mechanism(CKM.CKM_ECDSA_SHA256), "data"u8));
        var w = new BackgroundWork(login.Dispose);
        var t2 = new BackgroundWork(() => anchor.AcquireExclusive().Dispose());

        try
        {
            t1.Start();
            Assert.True(inContextLogin.Wait(Bounded, TestContext.Current.CancellationToken), "T1 never reached its context login");

            w.Start();
            Assert.True(SpinWait.SpinUntil(() => record.WaitingForExclusiveGate == 1, Bounded), "the final logout never queued on the gate");

            t2.Start();
            Assert.True(SpinWait.SpinUntil(() => record.WaitingForSharedGate == 1, Bounded), "T2 never queued on the gate");
        }
        finally
        {
            proceed.Set();
        }

        Assert.True(t1.Join(Bounded), "T1 (the sign that ends the login) deadlocked");
        Assert.True(w.Join(Bounded), "W (the final logout) deadlocked");
        Assert.True(t2.Join(Bounded), "T2 (the anchor's lease) deadlocked");

        Assert.Equal(CKR.CKR_PIN_LOCKED, Assert.IsAssignableFrom<Pkcs11Exception>(t1.Failure).ReturnValue);
        Assert.Null(w.Failure);
        // The login ended under T2's request, which closed the anchor: T2 finds it disposed.
        Assert.IsType<ObjectDisposedException>(t2.Failure);
        Assert.False(login.IsActive);
        Assert.False(record.IsLoggedIn);
        Assert.Equal(0, _module.LogoutCalls);

        key.Dispose();
        slotSession.Dispose();
        Assert.Empty(_module.OpenSessions);
    }

    // The waiting branch: a record send (a share's C_Login, parked in the module) holds the anchor's lock, and the
    // anchor's lease, asked for on another thread, waits for it instead of reporting concurrent use.
    [Fact]
    public void AnchorLease_WhileRecordSendHoldsAnchor_WaitsInsteadOfThrowing()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        Pkcs11SessionCore anchor = Assert.IsType<Pkcs11SessionCore>(Record.Anchor);
        ulong anchorId = anchor.SessionId;
        using var inLogin = new ManualResetEventSlim();
        using var proceed = new ManualResetEventSlim();
        _module.DuringLogin = session =>
        {
            if ((ulong)session != anchorId)
                return;
            inLogin.Set();
            proceed.Wait(Bounded);
        };

        Pkcs11Login? second = null;
        var sharing = new BackgroundWork(() => second = Slot.Login(TokenUser.User, _pin));

        bool leased = false;
        var leasing = new BackgroundWork(() =>
        {
            using (anchor.AcquireExclusive())
                leased = true;
        });

        try
        {
            sharing.Start();
            Assert.True(inLogin.Wait(Bounded, TestContext.Current.CancellationToken), "the share's C_Login never reached the module");

            leasing.Start();
            Assert.False(SpinWait.SpinUntil(() => !leasing.IsAlive, Watch),
                $"the anchor's lease did not wait for the record's send: {leasing.Failure}");
        }
        finally
        {
            proceed.Set();
            Assert.True(sharing.Join(Bounded), "the share did not finish");
            Assert.True(leasing.Join(Bounded), "the anchor's lease did not finish after the send");
        }

        Assert.Null(sharing.Failure);
        Assert.Null(leasing.Failure);
        Assert.True(leased);
        using Pkcs11Login shared = Assert.IsType<Pkcs11Login>(second);
        Assert.True(shared.IsActive);
    }

    // The throwing branch: with no record send waiting or holding, a second application thread on the anchor is
    // concurrent use, refused as on any session.
    [Fact]
    public void AnchorLease_WhileAnotherApplicationThreadHoldsIt_Throws()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        Pkcs11SessionCore anchor = Assert.IsType<Pkcs11SessionCore>(Record.Anchor);
        using var held = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        Thread holder = HoldLease(anchor, held, release);
        try
        {
            BackgroundWork other = BackgroundWork.Run(() => anchor.AcquireExclusive().Dispose());
            Assert.True(other.Join(Bounded), "a second application thread on the anchor waited instead of throwing");

            var ex = Assert.IsType<InvalidOperationException>(other.Failure);
            Assert.Contains("Concurrent access", ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            release.Set();
            Assert.True(holder.Join(Bounded));
        }

        // Nothing was left behind: the application lease's mark is cleared (a leaked one would have every later
        // anchor lease that finds the lock taken refuse, with no application thread holding it), and the gate and
        // the lock are free.
        Assert.Equal(0, anchor.ApplicationHolderMark);
        using (anchor.AcquireExclusive())
            Assert.Equal(0, Record.WaitingForExclusiveGate);
        Assert.Equal(0, anchor.ApplicationHolderMark);
    }

    [Fact]
    public void OrdinarySession_ConcurrentUse_StillThrows()
    {
        using Pkcs11Session slotSession = Slot.OpenSession();
        Assert.False(slotSession.Core.IsAnchorSide);
        using var held = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        Thread holder = HoldLease(slotSession.Core, held, release);
        try
        {
            BackgroundWork other = BackgroundWork.Run(() => slotSession.Core.AcquireExclusive().Dispose());
            Assert.True(other.Join(Bounded), "a second thread on an ordinary session waited instead of throwing");

            var ex = Assert.IsType<InvalidOperationException>(other.Failure);
            Assert.Contains("Concurrent access", ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            release.Set();
            Assert.True(holder.Join(Bounded));
        }
    }
}
