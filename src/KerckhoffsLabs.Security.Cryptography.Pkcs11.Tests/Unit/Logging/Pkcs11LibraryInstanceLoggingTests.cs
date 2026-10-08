using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Logging;

/// <summary>
/// Coverage for the per-instance <see cref="ILoggerFactory"/> a <see cref="Pkcs11Library"/> is
/// constructed with — the only way the library logs. There is no process-wide logging state, so
/// these tests reset nothing between them.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11LibraryInstanceLoggingTests
{
    private sealed class SlotFake : FakeModule
    {
        protected override CKR C_GetSlotList(bool tokenPresent, NativeBuffer<NativeCULong> slotList, ref NativeCULong count)
        {
            if (slotList.IsNull) { count = (NativeCULong)1; return CKR.CKR_OK; }
            slotList.Span[0] = (NativeCULong)7;
            count = (NativeCULong)1;
            return CKR.CKR_OK;
        }
    }

    [Fact]
    public void ExplicitFactory_ReceivesTheLibrarysLogging()
    {
        var instanceCapture = new CapturingLogger();
        using var module = new SlotFake();
        using var library = module.Load(new CapturingLoggerFactory(instanceCapture));

        Assert.Contains(instanceCapture.Entries, e => e.Message.Contains("Initialize"));
    }

    [Fact]
    public void NoFactory_StillWorks_AndLogsNowhere()
    {
        // With no factory the library, and the slots it produces, use a null logger. Nothing can
        // capture that output, which is the point: there is no shared factory for it to fall back to.
        using var module = new SlotFake();
        using var library = module.Load();

        Assert.Single(library.GetSlotList());
    }

    /// <summary>
    /// Logging is configured per <see cref="Pkcs11Library"/> only. A public logging type would be a
    /// process-wide configuration channel — mutable state that every instance, and every test, shares.
    /// </summary>
    [Fact]
    public void Assembly_ExportsNoLoggingConfigurationTypes()
    {
        string[] loggingTypes =
            [.. typeof(Pkcs11Library).Assembly.GetExportedTypes()
                .Where(static t => t.Namespace == "KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging")
                .Select(static t => t.FullName!)];

        Assert.Empty(loggingTypes);
    }

    [Fact]
    public void TwoInstances_WithDifferentFactories_DoNotShareLogging()
    {
        var captureA = new CapturingLogger();
        var captureB = new CapturingLogger();
        // One module may be active at a time, so the two instances are two loads of the same module.
        using var module = new SlotFake();
        using var libraryA = module.Load(new CapturingLoggerFactory(captureA));
        using var libraryB = module.Load(new CapturingLoggerFactory(captureB));

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
        using var module = new SlotFake();
        using var library = module.Load(new CapturingLoggerFactory(capture));
        capture.Clear(); // isolate what the slot itself logs

        var slots = library.GetSlotList();

        Assert.Single(slots);
        // Pkcs11Slot's own constructor logs "Pkcs11Slot({SlotId})::ctor" — this is the slot's log
        // line, not the library's, proving the factory was actually handed down to the slot.
        Assert.Contains(capture.Entries, e => e.Message.Contains("Pkcs11Slot") && e.Message.Contains("ctor"));
    }
}
