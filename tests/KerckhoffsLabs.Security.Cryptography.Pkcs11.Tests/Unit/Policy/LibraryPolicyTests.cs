using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

// The requests name a gated legacy mechanism on purpose: what the policies say of it is under test.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

/// <summary>
/// <see cref="Pkcs11LibraryOptions.Policy"/>: a library policy that allows overrides is the default a session's own
/// policy replaces; one that does not is a ceiling every session of the library enforces as well as its own.
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

    private sealed class NoEncryptPolicy : ICryptoPolicy
    {
        public string Name => "NoEncrypt";
        public bool AllowsOverride => true;
        public PolicyDecision Evaluate(PolicyRequest request)
            => request is MechanismUseRequest { Operation: CryptoOperation.Encrypt }
                ? PolicyDecision.Deny("no encryption")
                : CryptoPolicy.AllowInsecure.Evaluate(request);
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
    public void NoLibraryPolicy_IsRecommended_AndASessionWithoutOneEnforcesIt()
    {
        using var library = Load(policy: null);
        using var session = ManagedToken.OpenSession(library);

        Assert.Same(CryptoPolicy.Recommended, library.Policy);
        Assert.Same(CryptoPolicy.Recommended, session.Policy);
    }

    [Fact]
    public void LibraryPolicyAllowingOverrides_ASessionPolicyReplacesIt()
    {
        using var library = Load(CryptoPolicy.Recommended);
        using var session = ManagedToken.OpenSession(library, CryptoPolicy.AllowInsecure);

        Assert.Same(CryptoPolicy.AllowInsecure, session.Policy);
        Assert.True(session.IsAllowedByPolicy(AesEcb));
    }

    [Fact]
    public void LibraryPolicyAllowingNoOverride_ASessionWithoutOneEnforcesIt_AndRefusesLeases()
    {
        using var library = Load(CryptoPolicy.NistApproved);
        using var session = ManagedToken.OpenSession(library);

        Assert.Same(CryptoPolicy.NistApproved, session.Policy);
        Assert.False(session.IsAllowedByPolicy(ChaChaPoly));
        Assert.Throws<InvalidOperationException>(() => session.UsePolicy(CryptoPolicy.AllowInsecure));
    }

    // The point of the ceiling: code that opens its session with a looser policy does not get past the library's.
    [Fact]
    public void Ceiling_ALooserSessionPolicy_DoesNotLoosenIt()
    {
        using var library = Load(CryptoPolicy.NistApproved);
        using var session = ManagedToken.OpenSession(library, CryptoPolicy.AllowInsecure);

        Assert.False(session.IsAllowedByPolicy(ChaChaPoly));
        Assert.False(session.Policy.AllowsOverride);
        Assert.Throws<InvalidOperationException>(() => session.UsePolicy(CryptoPolicy.AllowInsecure));
        Assert.Equal("AllowInsecure within NistApproved", session.Policy.Name);
    }

    [Fact]
    public void Ceiling_AStricterSessionPolicy_NarrowsIt()
    {
        using var library = Load(CryptoPolicy.NistApproved);
        using var session = ManagedToken.OpenSession(library, new NoEncryptPolicy());

        Assert.False(session.IsAllowedByPolicy(new MechanismUseRequest(new Mechanism(CKM.CKM_AES_GCM), CryptoOperation.Encrypt)));
        Assert.True(session.IsAllowedByPolicy(AesGcmDecrypt));
    }

    [Fact]
    public void Ceiling_ItsRefusal_NamesTheLibrarysPolicy()
    {
        using var library = Load(CryptoPolicy.NistApproved);
        using var session = ManagedToken.OpenSession(library, CryptoPolicy.AllowInsecure);

        PolicyDecision decision = session.Policy.Evaluate(ChaChaPoly);

        Assert.False(decision.IsAllowed);
        Assert.EndsWith("(the library's NistApproved policy)", decision.Reason);
    }

    [Fact]
    public void Ceiling_AppliesToASlotSessionToo()
    {
        using var library = Load(CryptoPolicy.NistApproved);
        using var session = Slot(library).OpenSession(SessionAccess.ReadOnly, CryptoPolicy.AllowInsecure);

        Assert.False(session.IsAllowedByPolicy(ChaChaPoly));
        Assert.Throws<InvalidOperationException>(() => session.UsePolicy(CryptoPolicy.AllowInsecure));
    }

    [Fact]
    public void Ceiling_TheLibrarysOwnPolicyAsTheSessionPolicy_IsNotWrapped()
    {
        using var library = Load(CryptoPolicy.NistApproved);
        using var session = ManagedToken.OpenSession(library, CryptoPolicy.NistApproved);

        Assert.Same(CryptoPolicy.NistApproved, session.Policy);
    }
}
