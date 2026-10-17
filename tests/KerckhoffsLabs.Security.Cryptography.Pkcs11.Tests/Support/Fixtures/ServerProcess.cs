using System.Diagnostics;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// A child process whose stdout and stderr lines go to a callback as they arrive, so a chatty child
/// never blocks on a full pipe.
/// </summary>
internal sealed class ServerProcess : IDisposable
{
    private readonly Process _process;

    private ServerProcess(Process process) => _process = process;

    public int Id => _process.Id;
    public bool HasExited => _process.HasExited;
    public int ExitCode => _process.ExitCode;

    /// <summary>Starts the process with the test host's environment changed by <paramref name="environment"/>: a <see langword="null"/> value removes a variable.</summary>
    public static ServerProcess Start(string fileName, IReadOnlyList<string> arguments, string workingDirectory,
        IReadOnlyDictionary<string, string?> environment, Action<string> onLine)
    {
        var psi = new ProcessStartInfo(fileName)
        {
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (string argument in arguments) psi.ArgumentList.Add(argument);
        foreach (var (name, value) in environment)
        {
            if (value is null) psi.Environment.Remove(name);
            else psi.Environment[name] = value;
        }

        var process = new Process { StartInfo = psi };
        process.OutputDataReceived += (_, e) => { if (e.Data is not null) onLine(e.Data); };
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) onLine(e.Data); };
        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        return new ServerProcess(process);
    }

    /// <summary>Waits for an exited process's output to be read to its end.</summary>
    public void WaitForOutput() => _process.WaitForExit();

    /// <summary>Ends the process if it is still running and waits up to <paramref name="timeout"/>.</summary>
    public void Kill(TimeSpan timeout)
    {
        if (_process.HasExited) return;
        _process.Kill(entireProcessTree: true);
        _process.WaitForExit(timeout);
    }

    public void Dispose() => _process.Dispose();
}
