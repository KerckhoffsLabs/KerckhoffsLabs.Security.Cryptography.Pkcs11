using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// A child process whose stdout and stderr lines go to a callback, and which inherits nothing else
/// from the test host.
/// </summary>
/// <remarks>
/// On Windows, <see cref="Process.Start()"/> creates the child with handle inheritance on, so it gets
/// every inheritable handle the test host has open at that moment. Native backends open such handles:
/// SoftHSM opens its token files with <c>_open</c> and no <c>_O_NOINHERIT</c>, and a server holding one
/// makes SoftHSM's <c>C_DestroyObject</c> fail, since Windows will not delete a file another process has
/// open. So on Windows the child is created with <c>CreateProcessW</c> and a
/// <c>PROC_THREAD_ATTRIBUTE_HANDLE_LIST</c> naming its three stdio pipes only. On Unix an inherited fd
/// blocks nothing, and <see cref="Process"/> is used as is.
/// </remarks>
internal abstract partial class ServerProcess : IDisposable
{
    public abstract int Id { get; }
    public abstract bool HasExited { get; }
    public abstract int ExitCode { get; }

    /// <summary>Ends the process if it is still running and waits up to <paramref name="timeout"/>.</summary>
    public abstract void Kill(TimeSpan timeout);

    /// <summary>Waits for an exited process's output to be read to its end.</summary>
    public abstract void WaitForOutput();

    public abstract void Dispose();

    public static ServerProcess Start(string fileName, IReadOnlyList<string> arguments, string workingDirectory,
        IReadOnlyDictionary<string, string> environment, Action<string> onLine) =>
        OperatingSystem.IsWindows()
            ? WindowsServerProcess.Create(fileName, arguments, workingDirectory, environment, onLine)
            : new PortableServerProcess(fileName, arguments, workingDirectory, environment, onLine);

    private sealed class PortableServerProcess : ServerProcess
    {
        private readonly Process _process;

        public PortableServerProcess(string fileName, IReadOnlyList<string> arguments, string workingDirectory,
            IReadOnlyDictionary<string, string> environment, Action<string> onLine)
        {
            var psi = new ProcessStartInfo(fileName)
            {
                WorkingDirectory = workingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            foreach (string argument in arguments) psi.ArgumentList.Add(argument);
            foreach (var (name, value) in environment) psi.Environment[name] = value;

            _process = new Process { StartInfo = psi };
            _process.OutputDataReceived += (_, e) => { if (e.Data is not null) onLine(e.Data); };
            _process.ErrorDataReceived += (_, e) => { if (e.Data is not null) onLine(e.Data); };
            _process.Start();
            _process.BeginOutputReadLine();
            _process.BeginErrorReadLine();
        }

        public override int Id => _process.Id;
        public override bool HasExited => _process.HasExited;
        public override int ExitCode => _process.ExitCode;
        public override void WaitForOutput() => _process.WaitForExit();

        public override void Kill(TimeSpan timeout)
        {
            if (_process.HasExited) return;
            _process.Kill(entireProcessTree: true);
            _process.WaitForExit(timeout);
        }

        public override void Dispose() => _process.Dispose();
    }

    private sealed partial class WindowsServerProcess : ServerProcess
    {
        private readonly SafeProcessHandle _handle;
        private readonly Task[] _readers;

        private WindowsServerProcess(int id, SafeProcessHandle handle, Task[] readers)
        {
            Id = id;
            _handle = handle;
            _readers = readers;
        }

        public override int Id { get; }
        public override bool HasExited => WaitForSingleObject(_handle, 0) == WaitObject0;

        public override int ExitCode =>
            GetExitCodeProcess(_handle, out uint code) ? unchecked((int)code) : throw new Win32Exception();

        public override void WaitForOutput() => Task.WaitAll(_readers, TimeSpan.FromSeconds(10));

        public override void Kill(TimeSpan timeout)
        {
            if (HasExited) return;
            // `dotnet app.dll` runs the app inside the host process: there is no tree to walk.
            TerminateProcess(_handle, 1);
            WaitForSingleObject(_handle, (uint)timeout.TotalMilliseconds);
        }

        public override void Dispose() => _handle.Dispose();

        public static WindowsServerProcess Create(string fileName, IReadOnlyList<string> arguments, string workingDirectory,
            IReadOnlyDictionary<string, string> environment, Action<string> onLine)
        {
            using var stdin = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.Inheritable);
            var stdout = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
            var stderr = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
            nint[] inherited =
            [
                stdin.ClientSafePipeHandle.DangerousGetHandle(),
                stdout.ClientSafePipeHandle.DangerousGetHandle(),
                stderr.ClientSafePipeHandle.DangerousGetHandle(),
            ];

            nint attributes = 0;
            GCHandle pinned = GCHandle.Alloc(inherited, GCHandleType.Pinned);
            try
            {
                nuint size = 0;
                InitializeProcThreadAttributeList(0, 1, 0, ref size);
                attributes = Marshal.AllocHGlobal((nint)size);
                if (!InitializeProcThreadAttributeList(attributes, 1, 0, ref size))
                    throw new Win32Exception();
                if (!UpdateProcThreadAttribute(attributes, 0, ProcThreadAttributeHandleList, pinned.AddrOfPinnedObject(),
                        (nuint)(inherited.Length * nint.Size), 0, 0))
                    throw new Win32Exception();

                var startup = new StartupInfoEx
                {
                    StartupInfo = new StartupInfo
                    {
                        cb = Marshal.SizeOf<StartupInfoEx>(),
                        dwFlags = StartfUseStdHandles,
                        hStdInput = inherited[0],
                        hStdOutput = inherited[1],
                        hStdError = inherited[2],
                    },
                    lpAttributeList = attributes,
                };

                // CreateProcessW may write into the command line, so it gets a buffer of its own.
                string commandLine = string.Join(' ', new[] { fileName }.Concat(arguments).Select(Quote));
                char[] commandLineBuffer = (commandLine + '\0').ToCharArray();
                char[] environmentBlock = EnvironmentBlock(environment).ToCharArray();
                if (!CreateProcessW(null, commandLineBuffer, 0, 0, true,
                        ExtendedStartupInfoPresent | CreateUnicodeEnvironment | CreateNoWindow,
                        environmentBlock, workingDirectory, ref startup, out ProcessInformation info))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), $"CreateProcessW failed for {commandLine}");

                CloseHandle(info.hThread);
                // The child has its ends now; dropping ours lets the readers see end-of-file when it exits.
                stdout.DisposeLocalCopyOfClientHandle();
                stderr.DisposeLocalCopyOfClientHandle();
                return new WindowsServerProcess(info.dwProcessId, new SafeProcessHandle(info.hProcess, ownsHandle: true),
                    [ReadLines(stdout, onLine), ReadLines(stderr, onLine)]);
            }
            catch
            {
                stdout.Dispose();
                stderr.Dispose();
                throw;
            }
            finally
            {
                if (attributes != 0)
                {
                    DeleteProcThreadAttributeList(attributes);
                    Marshal.FreeHGlobal(attributes);
                }
                pinned.Free();
            }
        }

        private static Task ReadLines(AnonymousPipeServerStream pipe, Action<string> onLine) => Task.Run(() =>
        {
            using (pipe)
            using (var reader = new StreamReader(pipe))
            {
                while (reader.ReadLine() is { } line) onLine(line);
            }
        });

        // CommandLineToArgvW rules: quote, double the backslashes that precede a quote, escape quotes.
        private static string Quote(string argument)
        {
            if (argument.Length > 0 && argument.IndexOfAny([' ', '\t', '"']) < 0) return argument;
            var sb = new StringBuilder("\"");
            int backslashes = 0;
            foreach (char c in argument)
            {
                if (c == '\\') { backslashes++; continue; }
                sb.Append('\\', c == '"' ? backslashes * 2 + 1 : backslashes).Append(c);
                backslashes = 0;
            }
            return sb.Append('\\', backslashes * 2).Append('"').ToString();
        }

        private static string EnvironmentBlock(IReadOnlyDictionary<string, string> overrides)
        {
            var variables = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (System.Collections.DictionaryEntry e in Environment.GetEnvironmentVariables())
                variables[(string)e.Key] = (string?)e.Value ?? "";
            foreach (var (name, value) in overrides) variables[name] = value;
            var sb = new StringBuilder();
            foreach (var (name, value) in variables) sb.Append(name).Append('=').Append(value).Append('\0');
            return sb.Append('\0').ToString();
        }

        private const uint WaitObject0 = 0;
        private const int StartfUseStdHandles = 0x100;
        private const uint ExtendedStartupInfoPresent = 0x80000;
        private const uint CreateUnicodeEnvironment = 0x400;
        private const uint CreateNoWindow = 0x8000000;
        private const nuint ProcThreadAttributeHandleList = 0x20002;

        [StructLayout(LayoutKind.Sequential)]
        private struct StartupInfo
        {
            public int cb;
            public nint lpReserved, lpDesktop, lpTitle;
            public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public short wShowWindow, cbReserved2;
            public nint lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StartupInfoEx
        {
            public StartupInfo StartupInfo;
            public nint lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInformation
        {
            public nint hProcess, hThread;
            public int dwProcessId, dwThreadId;
        }

        [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool CreateProcessW(string? applicationName, char[] commandLine, nint processAttributes,
            nint threadAttributes, [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint creationFlags, char[] environment,
            string currentDirectory, ref StartupInfoEx startupInfo, out ProcessInformation processInformation);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool InitializeProcThreadAttributeList(nint list, int count, int flags, ref nuint size);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool UpdateProcThreadAttribute(nint list, uint flags, nuint attribute, nint value,
            nuint size, nint previousValue, nint returnSize);

        [LibraryImport("kernel32.dll")]
        private static partial void DeleteProcThreadAttributeList(nint list);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool CloseHandle(nint handle);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        private static partial uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool GetExitCodeProcess(SafeProcessHandle handle, out uint exitCode);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool TerminateProcess(SafeProcessHandle handle, uint exitCode);
    }
}
