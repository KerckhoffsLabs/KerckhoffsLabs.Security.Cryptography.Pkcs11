using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

/// <summary>
/// Test double for <see cref="ILowLevelPkcs11Library"/>. Every cryptoki method throws
/// <see cref="NotSupportedException"/> by default so an unexpected call surfaces loudly;
/// a test overrides only the methods its scenario exercises. Session-tracking members are
/// no-ops so a <c>Pkcs11Session</c> can be constructed over the fake.
/// </summary>
/// <remarks>
/// Inherits the ~90 Cryptoki method stubs from <see cref="NotSupportedPkcs11Library"/> — the
/// same base <c>ManagedSoftToken</c> derives from — rather than re-declaring them: the two
/// fakes need different behaviour for an un-overridden call (throw here vs. return
/// <see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> there), so overriding just <see cref="NotSupported"/>
/// keeps that one difference from re-duplicating every method signature.
/// </remarks>
internal class FakeLowLevelPkcs11Library : NotSupportedPkcs11Library
{
    public override bool IsV32ApiSupported => true;

    protected override CKR NotSupported(string method) => throw new NotSupportedException(method);
}
