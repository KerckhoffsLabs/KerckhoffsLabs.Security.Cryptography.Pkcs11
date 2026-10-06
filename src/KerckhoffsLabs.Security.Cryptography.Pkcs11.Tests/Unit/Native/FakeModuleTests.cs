using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// The guarantees the <see cref="FakeModule"/> host makes to the tests built on it: calls really go
/// through the library's loader and wrappers, an unimplemented function is a NULL slot, the module
/// sees the pointers the library actually passes, faults are contained, and module instances do not
/// leak into each other.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class FakeModuleTests
{
    [Fact]
    public void Calls_CrossTheRealLoaderAndStructMarshalling()
    {
        using var module = new InfoModule("Fake Module Inc.");
        using Pkcs11Library library = module.Load();

        LibraryInfo info = library.GetInfo();

        // CK_INFO travelled through the wrappers (Pack=1 on Windows) and back as text.
        Assert.Equal("Fake Module Inc.", info.ManufacturerId);
        Assert.Equal(1, module.CallCount("C_Initialize"));
        Assert.Equal(1, module.CallCount("C_GetInfo"));
    }

    [Fact]
    public void FunctionNotOverridden_IsANullSlot_AndTheLibraryReportsItUnsupported()
    {
        using var module = new InfoModule("x");
        using Pkcs11Library library = module.Load();

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => library.GetSlotList());

        Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
        Assert.Equal(0, module.CallCount("C_GetSlotList")); // never reached the module
    }

    [Fact]
    public void Module_SeesThePointersTheLibraryPasses_IncludingTheLengthProbe()
    {
        using var module = new SigningModule(signature: [1, 2, 3, 4, 5]);
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        using var session = new Pkcs11Session(lowLevel, (ulong)module.OpenSession());

        byte[] signature = session.Sign(new Mechanism(CKM.CKM_ECDSA_SHA256), new ObjectHandle(7), "data"u8);

        Assert.Equal([1, 2, 3, 4, 5], signature);
        Assert.Equal([true, false], module.OutputWasNull);  // NULL probe first, then the real buffer
        Assert.Equal("data", module.LastData);
        Assert.Equal((ulong)CKM.CKM_ECDSA_SHA256, module.LastMechanism);
    }

    [Fact]
    public void ExceptionInAModuleFunction_ReturnsGeneralError_AndIsRethrownOnDispose()
    {
        var module = new ThrowingModule();
        using (Pkcs11Library library = module.Load())
        {
            var ex = Assert.ThrowsAny<Pkcs11Exception>(() => library.GetInfo());
            Assert.Equal(CKR.CKR_GENERAL_ERROR, ex.ReturnValue);
        }

        var rethrown = Assert.Throws<InvalidOperationException>(module.Dispose);
        Assert.Equal("module fault", rethrown.Message);
    }

    [Fact]
    public void OnlyOneModule_IsActiveAtATime()
    {
        using var first = new InfoModule("first");

        Assert.Throws<InvalidOperationException>(() => new InfoModule("second"));
    }

    [Fact]
    public void SessionHandleOfADisposedModule_NeverReachesTheNextModule()
    {
        NativeCULong staleSession;
        using (var first = new SigningModule(signature: [9]))
            staleSession = first.OpenSession();

        using var second = new SigningModule(signature: [9]);
        using LowLevelPkcs11Library lowLevel = second.LoadLowLevel();

        // A session finalized after its test ended carries the old instance's id.
        Assert.Equal(CKR.CKR_SESSION_HANDLE_INVALID, lowLevel.C_CloseSession(staleSession));
        Assert.Equal(0, second.CallCount("C_CloseSession"));
    }

    private sealed class InfoModule(string manufacturer) : FakeModule
    {
        protected override CKR C_GetInfo(ref CK_INFO info)
        {
            info.CryptokiVersion = new CK_VERSION { Major = 2, Minor = 40 };
            Span<byte> field = info.ManufacturerId;
            field.Fill((byte)' ');
            Encoding.ASCII.GetBytes(manufacturer).CopyTo(field);
            return CKR.CKR_OK;
        }
    }

    private sealed class ThrowingModule : FakeModule
    {
        protected override CKR C_GetInfo(ref CK_INFO info) => throw new InvalidOperationException("module fault");
    }

    private sealed class SigningModule(byte[] signature) : FakeModule
    {
        public List<bool> OutputWasNull { get; } = [];
        public string? LastData { get; private set; }
        public ulong LastMechanism { get; private set; }

        public NativeCULong OpenSession() => NewSessionHandle();

        protected override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;

        protected override CKR C_SignInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key)
        {
            LastMechanism = (ulong)mechanism.Mechanism;
            return CKR.CKR_OK;
        }

        protected override CKR C_Sign(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> output, ref NativeCULong length)
        {
            OutputWasNull.Add(output.IsNull);
            LastData = Encoding.ASCII.GetString(data);
            if (!output.IsNull)
                signature.CopyTo(output.Span);
            length = (NativeCULong)(ulong)signature.Length;
            return CKR.CKR_OK;
        }
    }
}
