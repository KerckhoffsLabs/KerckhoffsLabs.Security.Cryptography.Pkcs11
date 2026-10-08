using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// Hermetic coverage for Pkcs11Library.GetInterfaces' zero-interfaces case — a v3.x module that
/// implements C_GetInterfaceList but currently reports none. Distinct from
/// <see cref="GetInterfaceTests"/>, which covers the single-interface lookup
/// (<see cref="Pkcs11Library.GetInterface"/>) including its v2.40 not-supported path.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class GetInterfacesTests
{
    private sealed class NoInterfacesFake : FakeModule
    {
        protected override CKR C_GetInterfaceList(bool listIsNull, Span<CK_INTERFACE> interfaces, ref NativeCULong count)
        {
            count = (NativeCULong)0;
            return CKR.CKR_OK;
        }
    }

    [Fact]
    public void ZeroInterfaces_ReturnsEmptyWithoutASecondCall()
    {
        using var module = new NoInterfacesFake();
        using var library = module.Load();

        Assert.Empty(library.GetInterfaces());
    }
}
