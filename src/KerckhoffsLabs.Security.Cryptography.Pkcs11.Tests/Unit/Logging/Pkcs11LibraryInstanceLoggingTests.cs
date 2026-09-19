using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Logging;

/// <summary>
/// Coverage for the per-instance <see cref="ILoggerFactory"/> a <see cref="Pkcs11Library"/> can be
/// constructed with, instead of relying solely on the shared, process-wide <see cref="Pkcs11Logging"/>
/// factory. Resets <see cref="Pkcs11Logging"/> around each test in case another test in the process
/// left it configured — these tests must observe only the factory passed at construction.
/// </summary>
public sealed class Pkcs11LibraryInstanceLoggingTests
{
    private sealed class SlotFake : NotSupportedPkcs11Library
    {
        public override CKR C_Initialize(CK_C_INITIALIZE_ARGS? initArgs) => CKR.CKR_OK;
        public override CKR C_Finalize(IntPtr reserved) => CKR.CKR_OK;

        public override CKR C_GetSlotList(bool tokenPresent, NativeCULong[]? slotList, ref NativeCULong count)
        {
            if (slotList is null) { count = (NativeCULong)1; return CKR.CKR_OK; }
            slotList[0] = (NativeCULong)7;
            count = (NativeCULong)1;
            return CKR.CKR_OK;
        }
    }

    [Fact]
    public void ExplicitFactory_UsedInsteadOfSharedPkcs11Logging()
    {
        // Deliberately does not touch Pkcs11Logging's process-global factory: that state is shared
        // with every other test in the suite, so asserting on its *absence* of an entry is racy under
        // parallel execution (another test can legitimately log into it at any moment). The claim this
        // test needs — the explicit factory is used instead of the shared one — is fully provable from
        // the instance capture alone.
        var instanceCapture = new CapturingLogger();
        using var library = new Pkcs11Library(new SlotFake(), new CapturingLoggerFactory(instanceCapture));

        Assert.Contains(instanceCapture.Entries, e => e.Message.Contains("Initialize"));
    }

    [Fact]
    public void NoFactory_FallsBackToSharedPkcs11Logging()
    {
        Pkcs11Logging.SetLoggerFactory(null);
        try
        {
            var sharedCapture = new CapturingLogger();
            Pkcs11Logging.SetLoggerFactory(new CapturingLoggerFactory(sharedCapture));

            using var library = new Pkcs11Library(new SlotFake());

            Assert.Contains(sharedCapture.Entries, e => e.Message.Contains("Initialize"));
        }
        finally { Pkcs11Logging.SetLoggerFactory(null); }
    }

    [Fact]
    public void TwoInstances_WithDifferentFactories_DoNotShareLogging()
    {
        var captureA = new CapturingLogger();
        var captureB = new CapturingLogger();
        using var libraryA = new Pkcs11Library(new SlotFake(), new CapturingLoggerFactory(captureA));
        using var libraryB = new Pkcs11Library(new SlotFake(), new CapturingLoggerFactory(captureB));

        Assert.Contains(captureA.Entries, e => e.Message.Contains("Initialize"));
        Assert.Contains(captureB.Entries, e => e.Message.Contains("Initialize"));
        // Each instance's ctor line reached only its own factory, not the other instance's.
        Assert.Equal(1, captureA.Entries.Count(e => e.Message.Contains("Initialize")));
        Assert.Equal(1, captureB.Entries.Count(e => e.Message.Contains("Initialize")));
    }

    [Fact]
    public void GetSlotList_ProducedSlot_InheritsTheLibrarysFactory()
    {
        var capture = new CapturingLogger();
        using var library = new Pkcs11Library(new SlotFake(), new CapturingLoggerFactory(capture));
        capture.Clear(); // isolate what the slot itself logs

        var slots = library.GetSlotList();

        Assert.Single(slots);
        // Pkcs11Slot's own constructor logs "Pkcs11Slot({SlotId})::ctor" — this is the slot's log
        // line, not the library's, proving the factory was actually handed down rather than the
        // slot falling back to the shared Pkcs11Logging factory.
        Assert.Contains(capture.Entries, e => e.Message.Contains("Pkcs11Slot") && e.Message.Contains("ctor"));
    }
}
