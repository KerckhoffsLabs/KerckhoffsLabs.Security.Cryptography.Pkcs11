using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

// The requests name a gated legacy mechanism on purpose: what the policies say of it is under test.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

/// <summary>
/// <see cref="Pkcs11LibraryOptions.Policy"/>: every session of the library enforces it. A scoped <c>UsePolicy</c> lease
/// can lift or tighten it where it allows overrides, and is refused where it does not.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class LibraryPolicyTests
{
    // Recommended allows it, NistApproved does not.
    private static readonly MechanismUseRequest ChaChaPoly =
        new(new Mechanism(CKM.CKM_CHACHA20_POLY1305), CryptoOperation.Encrypt);

    // AllowInsecure allows it, Recommended does not.
    private static readonly MechanismUseRequest AesEcb = new(new Mechanism(CKM.CKM_AES_ECB), CryptoOperation.Encrypt);

    // NistApproved allows it.
    private static readonly MechanismUseRequest AesGcmDecrypt = new(new Mechanism(CKM.CKM_AES_GCM), CryptoOperation.Decrypt);

    // A custom policy that allows no override, as one built with AllowsOverride(false) would be.
    private sealed class NoOverridePolicy : ICryptoPolicy
    {
        public string Name => "NoOverride";
        public bool AllowsOverride => false;
        public PolicyDecision Evaluate(PolicyRequest request) => CryptoPolicy.Recommended.Evaluate(request);
    }

    private static Pkcs11Library Load(ICryptoPolicy? policy)
        => new ManagedSoftToken().Load(new Pkcs11LibraryOptions { Policy = policy });

    private static Pkcs11Slot Slot(Pkcs11Library library) => library.GetSlotByTokenLabel(ManagedSoftToken.TokenLabel);

    [Fact]
    public void Requests_AreJudgedAsTheTestsAssume()
    {
        Assert.True(CryptoPolicy.Recommended.Evaluate(ChaChaPoly).IsAllowed);
        Assert.False(CryptoPolicy.NistApproved.Evaluate(ChaChaPoly).IsAllowed);
        Assert.True(CryptoPolicy.AllowInsecure.Evaluate(ChaChaPoly).IsAllowed);
        Assert.False(CryptoPolicy.Recommended.Evaluate(AesEcb).IsAllowed);
        Assert.True(CryptoPolicy.AllowInsecure.Evaluate(AesEcb).IsAllowed);
        Assert.True(CryptoPolicy.NistApproved.Evaluate(AesGcmDecrypt).IsAllowed);
        Assert.True(CryptoPolicy.Recommended.AllowsOverride);
        Assert.False(CryptoPolicy.NistApproved.AllowsOverride);
    }

    [Fact]
    public void NoLibraryPolicy_IsRecommended_AndEverySessionEnforcesIt()
    {
        using var library = Load(policy: null);
        using var session = ManagedToken.OpenSession(library);

        Assert.Same(CryptoPolicy.Recommended, library.Policy);
        Assert.Same(CryptoPolicy.Recommended, session.Policy);
    }

    // Every way of opening a session: a login's, a slot's, and the one-call form.
    [Fact]
    public void EverySessionOfTheLibrary_EnforcesItsPolicy()
    {
        using var library = Load(CryptoPolicy.AllowInsecure);
        Pkcs11Slot slot = Slot(library);
        using var fromLogin = ManagedToken.OpenSession(library);
        using var fromSlot = slot.OpenSession(SessionAccess.ReadOnly);
        using var oneCall = slot.OpenLoggedInSession(LoginCredential.FromPinSource(() => new SecurePin("1234")));

        Assert.Same(CryptoPolicy.AllowInsecure, fromLogin.Policy);
        Assert.Same(CryptoPolicy.AllowInsecure, fromSlot.Policy);
        Assert.Same(CryptoPolicy.AllowInsecure, oneCall.Policy);
        Assert.True(fromLogin.IsAllowedByPolicy(AesEcb));
    }

    [Fact]
    public void LibraryPolicyAllowingOverrides_ALeaseLiftsItForItsScope()
    {
        using var library = Load(CryptoPolicy.Recommended);
        using var session = ManagedToken.OpenSession(library);

        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
            Assert.True(session.IsAllowedByPolicy(AesEcb));

        Assert.False(session.IsAllowedByPolicy(AesEcb));
        Assert.Same(CryptoPolicy.Recommended, session.Policy);
    }

    [Fact]
    public void LibraryPolicyAllowingOverrides_ALeaseTightensItForItsScope()
    {
        using var library = Load(CryptoPolicy.Recommended);
        using var session = ManagedToken.OpenSession(library);

        using (session.UsePolicy(CryptoPolicy.NistApproved))
            Assert.False(session.IsAllowedByPolicy(ChaChaPoly));

        Assert.True(session.IsAllowedByPolicy(ChaChaPoly));
    }

    public static TheoryData<string> NoOverridePolicies() => ["NistApproved", "NoOverride"];

    // The point of a library policy that allows no override: no code that opens a session gets past it.
    [Theory]
    [MemberData(nameof(NoOverridePolicies))]
    public void LibraryPolicyAllowingNoOverride_EverySessionRefusesEveryLease(string name)
    {
        ICryptoPolicy policy = name == "NistApproved" ? CryptoPolicy.NistApproved : new NoOverridePolicy();
        using var library = Load(policy);
        using var fromLogin = ManagedToken.OpenSession(library);
        using var fromSlot = Slot(library).OpenSession(SessionAccess.ReadOnly);

        foreach (Pkcs11Session session in new[] { fromLogin, fromSlot })
        {
            Assert.Throws<InvalidOperationException>(() => session.UsePolicy(CryptoPolicy.AllowInsecure));
            Assert.Throws<InvalidOperationException>(() => session.UsePolicy(CryptoPolicy.Recommended));
            Assert.Same(policy, session.Policy);
        }
    }

    [Fact]
    public void NistApprovedLibrary_RefusesWhatNistApprovedRefuses()
    {
        using var library = Load(CryptoPolicy.NistApproved);
        using var session = ManagedToken.OpenSession(library);

        Assert.False(session.IsAllowedByPolicy(ChaChaPoly));
        Assert.True(session.IsAllowedByPolicy(AesGcmDecrypt));
    }
}
