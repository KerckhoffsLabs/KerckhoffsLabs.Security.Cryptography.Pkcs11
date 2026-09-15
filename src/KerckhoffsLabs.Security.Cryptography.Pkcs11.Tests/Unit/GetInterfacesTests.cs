using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// Hermetic coverage for Pkcs11Library.GetInterfaces' zero-interfaces case — a v3.x module that
/// implements C_GetInterfaceList but currently reports none. Distinct from
/// <see cref="GetInterfaceTests"/>, which covers the single-interface lookup
/// (<see cref="Pkcs11Library.GetInterface"/>) including its v2.40 not-supported path.
/// </summary>
public sealed class GetInterfacesTests
{
    private sealed class NoInterfacesFake : NotSupportedPkcs11Library
    {
        public override CKR C_Initialize(CK_C_INITIALIZE_ARGS? initArgs) => CKR.CKR_OK;
        public override CKR C_Finalize(IntPtr reserved) => CKR.CKR_OK;

        public override CKR C_GetInterfaceList(CK_INTERFACE[]? interfaces, ref NativeCULong count)
        {
            count = (NativeCULong)0;
            return CKR.CKR_OK;
        }
    }

    [Fact]
    public void ZeroInterfaces_ReturnsEmptyWithoutASecondCall()
    {
        using var library = new Pkcs11Library(new NoInterfacesFake());

        Assert.Empty(library.GetInterfaces());
    }
}
