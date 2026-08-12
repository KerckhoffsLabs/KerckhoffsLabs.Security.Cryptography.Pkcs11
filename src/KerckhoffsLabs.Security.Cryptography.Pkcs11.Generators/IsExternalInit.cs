namespace System.Runtime.CompilerServices;

// netstandard2.0 (this project's target framework, required for a Roslyn analyzer) predates the
// `init` accessor. The C# compiler only recognizes this type by name, not by content, to allow
// `init` and positional `record` properties to compile against older target frameworks.
internal static class IsExternalInit;
