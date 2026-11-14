namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

/// <summary>The reference implementations <see cref="MechanismCoverageTestCases"/> compares tokens with, against published vectors.</summary>
[NoBackendCollection("Runs the managed reference ciphers only; touches no module.")]
public sealed class MechanismCoverageReferenceTests
{
    [Fact]
    public void References_MatchSp80038aVectors() => MechanismCoverageTestCases.Assert_References_MatchSp80038aVectors();
}
