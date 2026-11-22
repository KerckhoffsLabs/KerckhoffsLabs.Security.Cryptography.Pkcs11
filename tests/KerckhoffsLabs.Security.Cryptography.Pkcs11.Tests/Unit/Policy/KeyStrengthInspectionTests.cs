using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

/// <summary>
/// A policy that judges key strength but does not inspect keys (a wrapper around <see cref="CryptoPolicy.Cnsa20"/>
/// that does not forward <see cref="ICryptoPolicy.InspectsKeys"/>) is refused when it is installed, as the library's
/// policy or as a lease; <see cref="DelegatingCryptoPolicy"/> forwards it.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class KeyStrengthInspectionTests
{
    // The mistake the check is for: a hand-written wrapper that leaves InspectsKeys at its default.
    private sealed class ForgetfulWrapper(ICryptoPolicy inner) : ICryptoPolicy
    {
        public string Name => $"{inner.Name}+Logging";
        public bool AllowsOverride => inner.AllowsOverride;
        public PolicyDecision Evaluate(PolicyRequest request) => inner.Evaluate(request);
    }

    private sealed class Logging(ICryptoPolicy inner) : DelegatingCryptoPolicy(inner)
    {
        public List<PolicyRequest> Seen { get; } = [];

        public override string Name => $"{Inner.Name}+Logging";

        public override PolicyDecision Evaluate(PolicyRequest request)
        {
            Seen.Add(request);
            return Inner.Evaluate(request);
        }
    }

    private sealed class DenyUnknown : ICryptoPolicy
    {
        public string Name => "DenyUnknown";
        public bool AllowsOverride => true;
        public PolicyDecision Evaluate(PolicyRequest request) => request switch
        {
            MechanismUseRequest => PolicyDecision.Allow,
            _ => PolicyDecision.Deny("not recognised"),
        };
    }

    private sealed class ThrowsOnUnknown : ICryptoPolicy
    {
        public string Name => "ThrowsOnUnknown";
        public bool AllowsOverride => true;
        public PolicyDecision Evaluate(PolicyRequest request) => request is MechanismUseRequest
            ? PolicyDecision.Allow
            : throw new NotSupportedException(request.GetType().Name);
    }

    private sealed class AllowAll : ICryptoPolicy
    {
        public string Name => "AllowAll";
        public bool AllowsOverride => true;
        public PolicyDecision Evaluate(PolicyRequest request) => PolicyDecision.Allow;
    }

    [Fact]
    public void AWrapperThatDoesNotForwardInspectsKeys_IsRefusedAtLoad_BeforeTheModule()
    {
        using var token = new ManagedSoftToken();

        var ex = Assert.Throws<ArgumentException>(
            () => token.Load(new Pkcs11LibraryOptions { Policy = new ForgetfulWrapper(CryptoPolicy.Cnsa20) }));

        Assert.Equal("options", ex.ParamName);
        Assert.Contains("Cnsa20+Logging", ex.Message);
        Assert.Contains(nameof(ICryptoPolicy.InspectsKeys), ex.Message);
        Assert.Contains(nameof(DelegatingCryptoPolicy), ex.Message);
    }

    [Fact]
    public void AWrapperThatDoesNotForwardInspectsKeys_IsRefusedAsALease()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);

        var ex = Assert.Throws<ArgumentException>(() => session.UsePolicy(new ForgetfulWrapper(CryptoPolicy.Cnsa20)));

        Assert.Equal("policy", ex.ParamName);
        Assert.Same(CryptoPolicy.Recommended, session.Policy);
    }

    [Fact]
    public void ADelegatingWrapper_ForwardsInspectsKeys_AndStillChecksKeySizes()
    {
        var logging = new Logging(CryptoPolicy.Cnsa20);
        using var library = ManagedToken.NewLibrary(logging);
        using var session = ManagedToken.OpenSession(library);

        Assert.True(logging.InspectsKeys);
        Assert.False(logging.AllowsOverride);
        Assert.Equal("Cnsa20+Logging", logging.Name);
        Assert.False(session.IsAllowedByPolicy(new KeyStrengthRequest(CKK.CKK_AES, KeyStrengthSource.ExistingKey) { ValueLengthBytes = 16 }));
        Assert.Throws<CryptoPolicyViolationException>(() => session.GenerateAesKey(128));
        Assert.Contains(logging.Seen, r => r is KeyStrengthRequest);
    }

    [Fact]
    public void ADelegatingWrapper_ForwardsTheWrappedPolicysNameAndOverride_UnlessOverridden()
    {
        var plain = new PassThrough(CryptoPolicy.Recommended);

        Assert.Equal("Recommended", plain.Name);
        Assert.True(plain.AllowsOverride);
        Assert.True(plain.InspectsKeys);
        Assert.Throws<ArgumentNullException>(() => new PassThrough(null!));
    }

    private sealed class PassThrough(ICryptoPolicy inner) : DelegatingCryptoPolicy(inner)
    {
        public override PolicyDecision Evaluate(PolicyRequest request) => Inner.Evaluate(request);
    }

    public static TheoryData<string> PoliciesThatDoNotJudgeKeyStrength() =>
        ["DenyUnknown", "ThrowsOnUnknown", "AllowAll", "ForgetfulRecommended"];

    // A policy that decides every key-strength request alike, or throws on one, does not judge key strength: it loads,
    // as it did before the check.
    [Theory]
    [MemberData(nameof(PoliciesThatDoNotJudgeKeyStrength))]
    public void APolicyThatDoesNotJudgeKeyStrength_Loads(string name)
    {
        ICryptoPolicy policy = name switch
        {
            "DenyUnknown" => new DenyUnknown(),
            "ThrowsOnUnknown" => new ThrowsOnUnknown(),
            "AllowAll" => new AllowAll(),
            _ => new ForgetfulWrapper(CryptoPolicy.Recommended),
        };

        using var library = ManagedToken.NewLibrary(policy);
        using var session = ManagedToken.OpenSession(library);

        Assert.Same(policy, library.Policy);
        session.UsePolicy(policy).Dispose();
    }
}
