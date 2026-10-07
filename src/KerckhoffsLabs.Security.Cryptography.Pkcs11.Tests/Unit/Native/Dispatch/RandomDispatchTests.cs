using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native.Dispatch;

/// <summary>
/// The random-number wrappers, called through a module's function table: the seed reaches the module,
/// and the module fills exactly the buffer it was given.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class RandomDispatchTests
{
    private static readonly byte[] Seed = [0x5E, 0xED];

    private static readonly Dictionary<string, DispatchCase> Cases = new DispatchCase[]
    {
        new(nameof(LowLevelPkcs11Library.C_SeedRandom), l => l.C_SeedRandom(DispatchSmoke.Session, Seed)),
        new(nameof(LowLevelPkcs11Library.C_GenerateRandom), l => l.C_GenerateRandom(DispatchSmoke.Session, new byte[8])),
    }.ToDictionary(c => c.Function, StringComparer.Ordinal);

    public static TheoryData<string> Functions => [.. Cases.Keys];

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_ReachesTheModule(string function)
    {
        using var module = new RandomModule();

        Assert.Equal(CKR.CKR_OK, DispatchSmoke.ReachesTheModule(module, Cases[function]));
        Assert.Equal((ulong)DispatchSmoke.Session, (ulong)module.LastSession);
    }

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_OfAFunctionTheModuleLacks_ReturnsNotSupported(string function)
        => DispatchSmoke.ReportsAMissingFunctionUnsupported(Cases[function]);

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_AfterDispose_Throws_WithoutReachingTheModule(string function)
    {
        using var module = new RandomModule();
        DispatchSmoke.RefusesACallAfterDispose(module, Cases[function]);
    }

    [Fact]
    public void SeedRandom_PassesTheSeed()
    {
        using var module = new RandomModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        lowLevel.C_SeedRandom(DispatchSmoke.Session, Seed);

        Assert.Equal(Seed, module.LastSeed);
    }

    [Fact]
    public void GenerateRandom_FillsTheWholeBuffer()
    {
        using var module = new RandomModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        byte[] random = new byte[24];

        Assert.Equal(CKR.CKR_OK, lowLevel.C_GenerateRandom(DispatchSmoke.Session, random));

        Assert.Equal(24, module.LastLength);
        Assert.All(random, b => Assert.Equal(0xA5, b));
    }

    private sealed class RandomModule : FakeModule
    {
        public NativeCULong LastSession { get; private set; }
        public byte[]? LastSeed { get; private set; }
        public int LastLength { get; private set; }

        protected override CKR C_SeedRandom(NativeCULong session, ReadOnlySpan<byte> seed)
        {
            LastSession = session;
            LastSeed = seed.ToArray();
            return CKR.CKR_OK;
        }

        protected override CKR C_GenerateRandom(NativeCULong session, Span<byte> randomData)
        {
            LastSession = session;
            LastLength = randomData.Length;
            randomData.Fill(0xA5);
            return CKR.CKR_OK;
        }
    }
}
