using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

#pragma warning disable KLPKCS11007, KLPKCS11008, KLPKCS11009, KLPKCS11010 // weak inputs are the subject under test

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

/// <summary>Tests for <see cref="SecureOnlyPolicy.WithAllowedMechanism(CKM, IEnumerable{CryptoOperation}, string)"/>
/// and its vendor-mechanism overload: a new, wider instance that adds to (never removes from) what the
/// receiver allows.</summary>
public sealed class SecureOnlyPolicyExtensionTests
{
    private const ulong VendorMechanism = 0x8000_1234UL;
    private const string Reason = "Reviewed for this deployment.";

    private static bool Allowed(ICryptoPolicy policy, Mechanism mech, CryptoOperation op)
        => policy.Evaluate(new MechanismUseRequest(mech, op)).IsAllowed;

    private static bool Allowed(ICryptoPolicy policy, CKM mech, CryptoOperation op)
        => Allowed(policy, new Mechanism(mech), op);

    // === Identity ===========================================================

    [Fact]
    public void ExtendedInstance_IsNamedSecureOnlyCustom_AndStillAllowsOverride()
    {
        SecureOnlyPolicy extended = CryptoPolicy.SecureOnly.WithAllowedMechanism(
            CKM.CKM_DES_CBC, [CryptoOperation.Decrypt], Reason);

        Assert.Equal("SecureOnly+custom", extended.Name);
        Assert.True(extended.AllowsOverride);
    }

    // === Allowed only for the listed operations =============================

    [Fact]
    public void ExtendedMechanism_IsAllowedOnlyForTheListedOperations()
    {
        SecureOnlyPolicy extended = CryptoPolicy.SecureOnly.WithAllowedMechanism(
            CKM.CKM_DES_CBC, [CryptoOperation.Decrypt], Reason);

        Assert.True(Allowed(extended, CKM.CKM_DES_CBC, CryptoOperation.Decrypt));
        Assert.False(Allowed(extended, CKM.CKM_DES_CBC, CryptoOperation.Encrypt));
        Assert.False(Allowed(extended, CKM.CKM_DES_CBC, CryptoOperation.Sign));
    }

    // === Receiver and CryptoPolicy.SecureOnly unaffected =====================

    [Fact]
    public void Receiver_And_BaseSecureOnly_AreUnaffectedByExtension()
    {
        SecureOnlyPolicy receiver = CryptoPolicy.SecureOnly;
        var request = new MechanismUseRequest(new Mechanism(CKM.CKM_DES_CBC), CryptoOperation.Decrypt);

        bool receiverVerdictBefore = receiver.Evaluate(request).IsAllowed;
        bool baseVerdictBefore = CryptoPolicy.SecureOnly.Evaluate(request).IsAllowed;

        SecureOnlyPolicy extended = receiver.WithAllowedMechanism(CKM.CKM_DES_CBC, [CryptoOperation.Decrypt], Reason);

        Assert.Equal(receiverVerdictBefore, receiver.Evaluate(request).IsAllowed);
        Assert.Equal(baseVerdictBefore, CryptoPolicy.SecureOnly.Evaluate(request).IsAllowed);
        Assert.False(receiver.Evaluate(request).IsAllowed);
        Assert.False(CryptoPolicy.SecureOnly.Evaluate(request).IsAllowed);
        Assert.NotSame(receiver, extended);
        Assert.True(extended.Evaluate(request).IsAllowed);
    }

    // === Vendor mechanisms ====================================================

    [Fact]
    public void VendorMechanism_IsAllowedAfterExtension_ThroughTheUlongOverload()
    {
        Assert.False(Allowed(CryptoPolicy.SecureOnly, new Mechanism(VendorMechanism), CryptoOperation.Sign));

        SecureOnlyPolicy extended = CryptoPolicy.SecureOnly.WithAllowedMechanism(
            VendorMechanism, [CryptoOperation.Sign, CryptoOperation.Verify], Reason);

        Assert.True(Allowed(extended, new Mechanism(VendorMechanism), CryptoOperation.Sign));
        Assert.True(Allowed(extended, new Mechanism(VendorMechanism), CryptoOperation.Verify));
        Assert.False(Allowed(extended, new Mechanism(VendorMechanism), CryptoOperation.Encrypt));
        // Original untouched.
        Assert.False(Allowed(CryptoPolicy.SecureOnly, new Mechanism(VendorMechanism), CryptoOperation.Sign));
    }

    [Fact]
    public void Routing_IsByRawValue_RegardlessOfWhichOverloadIsUsed()
    {
        // A vendor-range value passed through the CKM overload still lands in the vendor table.
        const ulong vendorRaw = 0x8000_5678UL;
        SecureOnlyPolicy viaCkmOverload = CryptoPolicy.SecureOnly.WithAllowedMechanism(
            (CKM)vendorRaw, [CryptoOperation.Sign], Reason);
        Assert.True(viaCkmOverload.Catalogue.AllowedVendorMechanisms.ContainsKey(vendorRaw));
        Assert.False(viaCkmOverload.Catalogue.AllowedMechanisms.ContainsKey((CKM)vendorRaw));

        // A standard value passed through the ulong overload still lands in the standard table.
        SecureOnlyPolicy viaUlongOverload = CryptoPolicy.SecureOnly.WithAllowedMechanism(
            (ulong)CKM.CKM_DES_CBC, [CryptoOperation.Decrypt], Reason);
        Assert.True(viaUlongOverload.Catalogue.AllowedMechanisms.ContainsKey(CKM.CKM_DES_CBC));
        Assert.False(viaUlongOverload.Catalogue.AllowedVendorMechanisms.ContainsKey((ulong)CKM.CKM_DES_CBC));
    }

    // === Documented-refused mechanisms accepted ===============================

    [Fact]
    public void DocumentedRefusedMechanism_CkmDesCbc_IsAllowedForDecryptOnly_AfterExtension()
    {
        Assert.True(CryptoPolicy.SecureOnly.Catalogue.DocumentedRefusedMechanisms.ContainsKey(CKM.CKM_DES_CBC));

        SecureOnlyPolicy extended = CryptoPolicy.SecureOnly.WithAllowedMechanism(
            CKM.CKM_DES_CBC, [CryptoOperation.Decrypt], Reason);

        Assert.True(Allowed(extended, CKM.CKM_DES_CBC, CryptoOperation.Decrypt));
        Assert.False(Allowed(extended, CKM.CKM_DES_CBC, CryptoOperation.Encrypt));
        // It remains documented (documentation only — the allow-list entry decides the verdict now).
        Assert.True(extended.Catalogue.DocumentedRefusedMechanisms.ContainsKey(CKM.CKM_DES_CBC));
    }

    // === Chained extensions accumulate ========================================

    [Fact]
    public void ChainedExtensions_Accumulate()
    {
        SecureOnlyPolicy extended = CryptoPolicy.SecureOnly
            .WithAllowedMechanism(CKM.CKM_DES_CBC, [CryptoOperation.Decrypt], Reason)
            .WithAllowedMechanism(VendorMechanism, [CryptoOperation.Sign], Reason);

        Assert.True(Allowed(extended, CKM.CKM_DES_CBC, CryptoOperation.Decrypt));
        Assert.True(Allowed(extended, new Mechanism(VendorMechanism), CryptoOperation.Sign));
        Assert.Equal("SecureOnly+custom", extended.Name);
    }

    // === Never narrows: operations are unioned with any existing entry ======

    [Fact]
    public void ReAddingTheSameCustomMechanism_AccumulatesOperations_AndKeepsTheLatestReason()
    {
        SecureOnlyPolicy once = CryptoPolicy.SecureOnly.WithAllowedMechanism(
            VendorMechanism, [CryptoOperation.Encrypt, CryptoOperation.Decrypt], Reason);
        Assert.True(Allowed(once, new Mechanism(VendorMechanism), CryptoOperation.Encrypt));

        SecureOnlyPolicy twice = once.WithAllowedMechanism(VendorMechanism, [CryptoOperation.Sign], "Signing reviewed too.");

        Assert.True(Allowed(twice, new Mechanism(VendorMechanism), CryptoOperation.Sign));
        Assert.True(Allowed(twice, new Mechanism(VendorMechanism), CryptoOperation.Encrypt));
        Assert.True(Allowed(twice, new Mechanism(VendorMechanism), CryptoOperation.Decrypt));
        Assert.False(Allowed(twice, new Mechanism(VendorMechanism), CryptoOperation.Verify));
        Assert.Equal("Signing reviewed too.", twice.Catalogue.AllowedVendorMechanisms[VendorMechanism].Rationale);
    }

    [Fact]
    public void ExtendingAnUncheckedBuiltIn_KeepsItsOperations_AndItsRationale()
    {
        MechanismRule builtIn = CryptoPolicy.SecureOnly.Catalogue.AllowedMechanisms[CKM.CKM_AES_GCM];

        SecureOnlyPolicy extended = CryptoPolicy.SecureOnly.WithAllowedMechanism(
            CKM.CKM_AES_GCM, [CryptoOperation.Sign], Reason);

        foreach (CryptoOperation op in (CryptoOperation[])[
            CryptoOperation.Encrypt, CryptoOperation.Decrypt, CryptoOperation.Wrap, CryptoOperation.Unwrap, CryptoOperation.Sign])
            Assert.True(Allowed(extended, CKM.CKM_AES_GCM, op), $"CKM_AES_GCM {op}");
        Assert.False(Allowed(extended, CKM.CKM_AES_GCM, CryptoOperation.Verify));
        Assert.Equal($"{builtIn.Rationale} Extended: {Reason}", extended.Catalogue.AllowedMechanisms[CKM.CKM_AES_GCM].Rationale);
    }

    [Fact]
    public void ExtendingEcdhForAnotherOperation_KeepsDerive()
    {
        SecureOnlyPolicy extended = CryptoPolicy.SecureOnly.WithAllowedMechanism(
            CKM.CKM_ECDH1_DERIVE, [CryptoOperation.Encapsulate], Reason);

        Mechanism ecdh = SecureOnlyPolicyTests.ValidMechanismFor(CKM.CKM_ECDH1_DERIVE);
        Assert.True(Allowed(extended, ecdh, CryptoOperation.Derive));
        Assert.True(Allowed(extended, ecdh, CryptoOperation.Encapsulate));
    }

    [Fact]
    public void ExtendingABuiltInTwice_KeepsTheBuiltInRationale_WithTheLatestReason()
    {
        MechanismRule builtIn = CryptoPolicy.SecureOnly.Catalogue.AllowedMechanisms[CKM.CKM_AES_GCM];

        SecureOnlyPolicy extended = CryptoPolicy.SecureOnly
            .WithAllowedMechanism(CKM.CKM_AES_GCM, [CryptoOperation.Sign], "First.")
            .WithAllowedMechanism(CKM.CKM_AES_GCM, [CryptoOperation.Verify], "Second.");

        Assert.True(Allowed(extended, CKM.CKM_AES_GCM, CryptoOperation.Sign));
        Assert.True(Allowed(extended, CKM.CKM_AES_GCM, CryptoOperation.Verify));
        Assert.True(Allowed(extended, CKM.CKM_AES_GCM, CryptoOperation.Encrypt));
        Assert.Equal($"{builtIn.Rationale} Extended: Second.", extended.Catalogue.AllowedMechanisms[CKM.CKM_AES_GCM].Rationale);
    }

    // === Existing parameter checks are preserved, not dropped ================

    [Fact]
    public void ExtendingAnAlreadyCheckedMechanism_KeepsItsParameterCheck()
    {
        // CKM_RSA_PKCS_OAEP already has a built-in parameter check (an allowed OAEP hash is required).
        // Widening it must not let a caller silently bypass that check.
        SecureOnlyPolicy extended = CryptoPolicy.SecureOnly.WithAllowedMechanism(
            CKM.CKM_RSA_PKCS_OAEP, [CryptoOperation.Encrypt], "Re-approved for a new use case.");

        Assert.False(Allowed(extended, new Mechanism(CKM.CKM_RSA_PKCS_OAEP), CryptoOperation.Encrypt));
        Assert.False(Allowed(
            extended,
            new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA_1, CKG.CKG_MGF1_SHA1)),
            CryptoOperation.Encrypt));
        Assert.True(Allowed(
            extended,
            new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256)),
            CryptoOperation.Encrypt));
        // The built-in operations survive too, and the rationale keeps the built-in text.
        Assert.True(Allowed(
            extended,
            new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256)),
            CryptoOperation.Unwrap));
        Assert.StartsWith(
            CryptoPolicy.SecureOnly.Catalogue.AllowedMechanisms[CKM.CKM_RSA_PKCS_OAEP].Rationale,
            extended.Catalogue.AllowedMechanisms[CKM.CKM_RSA_PKCS_OAEP].Rationale,
            StringComparison.Ordinal);
    }

    [Fact]
    public void ExtendingACheckedBuiltInForANewOperation_AppliesTheCheckToIt()
    {
        SecureOnlyPolicy extended = CryptoPolicy.SecureOnly.WithAllowedMechanism(
            CKM.CKM_RSA_PKCS_OAEP, [CryptoOperation.Sign], Reason);

        Assert.False(Allowed(extended, new Mechanism(CKM.CKM_RSA_PKCS_OAEP), CryptoOperation.Sign));
        Assert.True(Allowed(
            extended,
            new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256)),
            CryptoOperation.Sign));
    }

    // === Mechanism values above 32 bits (CK_ULONG is 64-bit on Unix) ==========

    public static bool IsUnix => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    [Fact(SkipUnless = nameof(IsUnix), Skip = "Requires a 64-bit CK_ULONG")]
    public void MechanismValueAbove32Bits_IsDeniedByDefault_AndAllowedAfterExtension()
    {
        const ulong wide = 0x1_0000_0001UL;
        var mechanism = new Mechanism(wide);

        PolicyDecision denied = CryptoPolicy.SecureOnly.Evaluate(new MechanismUseRequest(mechanism, CryptoOperation.Sign));
        Assert.False(denied.IsAllowed);

        SecureOnlyPolicy extended = CryptoPolicy.SecureOnly.WithAllowedMechanism(wide, [CryptoOperation.Sign], Reason);
        Assert.True(Allowed(extended, mechanism, CryptoOperation.Sign));
        Assert.False(Allowed(extended, mechanism, CryptoOperation.Verify));
        Assert.True(extended.Catalogue.AllowedVendorMechanisms.ContainsKey(wide));
    }

    // === Denial wording on an extended instance ===============================

    [Fact]
    public void ExtendedInstance_UnlistedMechanismDenial_PointsAtBothExtensionReceivers()
    {
        SecureOnlyPolicy extended = CryptoPolicy.SecureOnly.WithAllowedMechanism(
            CKM.CKM_DES_CBC, [CryptoOperation.Decrypt], Reason);

        Assert.Equal(
            "CKM_CAMELLIA_CBC is not on the SecureOnly+custom allow-list (not reviewed). " +
            "If you have reviewed it, add it with WithAllowedMechanism(...) on CryptoPolicy.SecureOnly or this policy.",
            extended.Evaluate(new MechanismUseRequest(new Mechanism(CKM.CKM_CAMELLIA_CBC), CryptoOperation.Encrypt)).Reason);
    }

    // === Validation ============================================================

    [Fact]
    public void UndefinedOperation_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            CryptoPolicy.SecureOnly.WithAllowedMechanism(CKM.CKM_DES_CBC, [(CryptoOperation)32], Reason));
        Assert.Throws<ArgumentException>(() =>
            CryptoPolicy.SecureOnly.WithAllowedMechanism(VendorMechanism, [CryptoOperation.Decrypt, (CryptoOperation)(-1)], Reason));
    }

    [Fact]
    public void NullOperations_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            CryptoPolicy.SecureOnly.WithAllowedMechanism(CKM.CKM_DES_CBC, null!, Reason));
        Assert.Throws<ArgumentNullException>(() =>
            CryptoPolicy.SecureOnly.WithAllowedMechanism(VendorMechanism, null!, Reason));
    }

    [Fact]
    public void EmptyOperations_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            CryptoPolicy.SecureOnly.WithAllowedMechanism(CKM.CKM_DES_CBC, [], Reason));
        Assert.Throws<ArgumentException>(() =>
            CryptoPolicy.SecureOnly.WithAllowedMechanism(VendorMechanism, [], Reason));
    }

    // ArgumentException.ThrowIfNullOrWhiteSpace (the pattern PolicyDecision.Deny already uses) throws the
    // more specific ArgumentNullException for a null argument, which is itself an ArgumentException.
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void BlankReason_ThrowsArgumentException(string reason)
    {
        Assert.Throws<ArgumentException>(() =>
            CryptoPolicy.SecureOnly.WithAllowedMechanism(CKM.CKM_DES_CBC, [CryptoOperation.Decrypt], reason));
        Assert.Throws<ArgumentException>(() =>
            CryptoPolicy.SecureOnly.WithAllowedMechanism(VendorMechanism, [CryptoOperation.Decrypt], reason));
    }

    [Fact]
    public void NullReason_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            CryptoPolicy.SecureOnly.WithAllowedMechanism(CKM.CKM_DES_CBC, [CryptoOperation.Decrypt], null!));
        Assert.Throws<ArgumentNullException>(() =>
            CryptoPolicy.SecureOnly.WithAllowedMechanism(VendorMechanism, [CryptoOperation.Decrypt], null!));
    }

    // === Rationale rendered ====================================================

    [Fact]
    public void AddedEntry_RecordsTheCallersReasonAsItsRationale()
    {
        SecureOnlyPolicy extended = CryptoPolicy.SecureOnly.WithAllowedMechanism(
            CKM.CKM_DES_CBC, [CryptoOperation.Decrypt], Reason);

        Assert.Equal(Reason, extended.Catalogue.AllowedMechanisms[CKM.CKM_DES_CBC].Rationale);
    }
}
