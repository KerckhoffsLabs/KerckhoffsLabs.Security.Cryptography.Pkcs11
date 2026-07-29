using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.MechanismParams;

/// <summary>
/// A <c>Mechanism</c> owns the <c>MechanismParameters</c> it is constructed with. Before that was
/// true, the parameter object's unmanaged IV/AAD buffers survived until its finalizer ran whenever
/// the caller held no separate reference — which is the shape most call sites use
/// (<c>new Mechanism(ckm, new CkmAesGcmParams(...))</c>), so the buffers were routinely left to the
/// GC. These tests pin the ownership and the disposal properties callers depend on.
/// </summary>
public sealed class MechanismOwnsParametersTests
{
    private static CkmAesGcmParams NewParams() =>
        new(new byte[12], new byte[16], tagBits: 128);

    /// <summary>Disposing the mechanism must dispose the parameters it owns.</summary>
    [Fact]
    public void DisposingMechanism_DisposesOwnedParameters()
    {
        var parameters = NewParams();
        var mechanism = new Mechanism(CKM.CKM_AES_GCM, parameters);

        mechanism.Dispose();

        // ToMarshalableStructure is the parameter object's disposal-guarded entry point, so it
        // throwing is the observable proof that the mechanism disposed it.
        Assert.Throws<ObjectDisposedException>(() => parameters.ToMarshalableStructure());
    }

    /// <summary>
    /// The established call shape is <c>using var p = …; using var m = new Mechanism(…, p);</c>.
    /// A using declaration disposes in reverse order, so the mechanism goes first and the explicit
    /// disposal of the parameters follows — that second disposal must stay harmless.
    /// </summary>
    [Fact]
    public void DisposingParametersAfterTheMechanism_IsIdempotent()
    {
        var parameters = NewParams();

        using (var mechanism = new Mechanism(CKM.CKM_AES_GCM, parameters))
        {
            Assert.Equal((ulong)CKM.CKM_AES_GCM, mechanism.Type);
        }

        parameters.Dispose(); // must not throw, and must not double-free
        parameters.Dispose();
    }

    /// <summary>
    /// The inline shape used across the algorithm façades leaves the caller no reference to the
    /// parameters, so the mechanism is the only thing that can release them deterministically.
    /// </summary>
    [Fact]
    public void InlineParameters_AreReleasedByDisposingTheMechanism()
    {
        Mechanism mechanism = new(CKM.CKM_AES_GCM, NewParams());
        MechanismParameters? owned = mechanism.Parameters;
        Assert.NotNull(owned);

        mechanism.Dispose();

        Assert.Throws<ObjectDisposedException>(() => owned!.ToMarshalableStructure());
    }

    /// <summary>A mechanism built without parameters must still dispose cleanly.</summary>
    [Fact]
    public void MechanismWithoutParameters_DisposesCleanly()
    {
        var mechanism = new Mechanism(CKM.CKM_SHA256);
        Assert.Null(mechanism.Parameters);

        mechanism.Dispose();
        mechanism.Dispose();
    }
}
