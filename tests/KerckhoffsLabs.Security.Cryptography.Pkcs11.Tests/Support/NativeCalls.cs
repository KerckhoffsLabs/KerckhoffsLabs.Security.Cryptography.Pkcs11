using System.Globalization;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support;

/// <summary>
/// The native calls one public operation makes, counted on a <see cref="FakeModule"/>, for tests that pin what a path
/// costs. A pin is exact: a call added or removed fails it, so a change that alters a path's cost has to say so by
/// updating the pin (and the comment that explains it).
/// </summary>
internal static class NativeCalls
{
    /// <summary>
    /// The calls <paramref name="action"/> makes on <paramref name="module"/>, as <c>C_Name×count</c> in name order,
    /// joined by <c>", "</c>; an empty string when it makes none.
    /// </summary>
    public static string Of(FakeModule module, Action action)
    {
        Dictionary<string, int> before = module.Calls.ToDictionary(call => call.Key, call => call.Value);
        action();
        return Format(module.Calls
            .Select(call => (call.Key, Count: call.Value - before.GetValueOrDefault(call.Key)))
            .Where(call => call.Count != 0));
    }

    /// <summary>The number of calls a <see cref="Of(FakeModule, Action)"/> string counts.</summary>
    public static int Total(string calls)
        => calls.Length == 0 ? 0 : calls.Split(", ").Sum(call => int.Parse(call.AsSpan(call.IndexOf('×') + 1), CultureInfo.InvariantCulture));

    private static string Format(IEnumerable<(string Name, int Count)> calls)
        => string.Join(", ", calls.OrderBy(call => call.Name, StringComparer.Ordinal).Select(call => $"{call.Name}×{call.Count}"));
}
