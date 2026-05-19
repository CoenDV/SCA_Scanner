namespace SCAScanner;

using System.Diagnostics;
using System.Text;
using System.Threading;

public sealed class TrivySbomGenerator
{
    public sealed record TrivySbomResult(
        string OutputPath,
        string TargetPath,
        string? DiagnosticLogPath,
        bool HasDiagnostics);

    public string ResolveDefaultOutputPath()
    {
        string hostName = GetSafeHostName();
        string? reportsDir = Environment.GetEnvironmentVariable("REPORTS_DIR");
        string outputRoot;

        if (!string.IsNullOrWhiteSpace(reportsDir))
        {
            outputRoot = reportsDir;
        }
        else if (OperatingSystem.IsWindows())
        {
            string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            if (string.IsNullOrWhiteSpace(programData))
                programData = @"C:\ProgramData";

            outputRoot = Path.Combine(programData, "platform-scanning");
        }
        else if (OperatingSystem.IsMacOS())
        {
            outputRoot = "/Library/Application Support/platform-scanning";
        }
        else
        {
            outputRoot = "/var/lib/platform-scanning";
        }

        return Path.Combine(outputRoot, $"sbom-trivy-{hostName}.json");
    }

    public sealed class TrivySbomOptions
    {
        public string? TargetPath { get; init; }
        public TimeSpan Timeout { get; init; } = TimeSpan.FromMinutes(5);
        public string? TrivyTimeoutArgument { get; init; }
        public IReadOnlyList<string> SkipDirs { get; init; } = Array.Empty<string>();
        public IReadOnlyList<string> SkipFiles { get; init; } = Array.Empty<string>();
    }

    public TrivySbomResult GenerateSbom(string? outputPath, TrivySbomOptions options)
    {
        string trivyPath = ResolveTrivyPath();
        string finalOutput = string.IsNullOrWhiteSpace(outputPath) ? ResolveDefaultOutputPath() : outputPath;
        string fullOutput = Path.GetFullPath(finalOutput);

        string? outputDir = Path.GetDirectoryName(fullOutput);
        if (!string.IsNullOrWhiteSpace(outputDir))
            Directory.CreateDirectory(outputDir);

        string targetPath = ResolveTargetPath(options.TargetPath);

        var stdOut = new StringBuilder();
        var stdErr = new StringBuilder();

        var startInfo = new ProcessStartInfo
        {
            FileName = trivyPath,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            ArgumentList =
            {
                "fs",
                "--format", "cyclonedx",
                "--output", fullOutput
            }
        };

        if (!string.IsNullOrWhiteSpace(options.TrivyTimeoutArgument))
        {
            startInfo.ArgumentList.Add("--timeout");
            startInfo.ArgumentList.Add(options.TrivyTimeoutArgument);
        }

        if (options.SkipDirs.Count > 0)
        {
            startInfo.ArgumentList.Add("--skip-dirs");
            startInfo.ArgumentList.Add(string.Join(",", options.SkipDirs));
        }

        if (options.SkipFiles.Count > 0)
        {
            startInfo.ArgumentList.Add("--skip-files");
            startInfo.ArgumentList.Add(string.Join(",", options.SkipFiles));
        }

        startInfo.ArgumentList.Add(targetPath);

        using var process = new Process { StartInfo = startInfo };

        process.OutputDataReceived += (_, args) =>
        {
            if (args.Data is not null)
                stdOut.AppendLine(args.Data);
        };
        process.ErrorDataReceived += (_, args) =>
        {
            if (args.Data is not null)
                stdErr.AppendLine(args.Data);
        };

        if (!process.Start())
            throw new InvalidOperationException("Failed to start Trivy process.");

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        bool exited;
        if (options.Timeout == Timeout.InfiniteTimeSpan)
        {
            process.WaitForExit();
            exited = true;
        }
        else
        {
            int timeoutMs = options.Timeout.TotalMilliseconds > int.MaxValue
                ? int.MaxValue
                : (int)options.Timeout.TotalMilliseconds;
            exited = process.WaitForExit(timeoutMs);
        }

        if (!exited)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch
            {
                // Best-effort kill; if it fails, still treat as timeout.
            }

            throw new TimeoutException($"Trivy SBOM generation exceeded timeout of {options.Timeout}.");
        }

        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            string detail = stdErr.Length == 0 ? stdOut.ToString() : stdErr.ToString();
            throw new InvalidOperationException($"Trivy exited with code {process.ExitCode}: {detail.Trim()}");
        }

        if (!File.Exists(fullOutput))
            throw new InvalidOperationException($"Trivy completed but SBOM file was not created: {fullOutput}");

        string? diagnosticLogPath = WriteDiagnosticsLog(fullOutput, targetPath, stdOut.ToString(), stdErr.ToString());

        return new TrivySbomResult(
            fullOutput,
            targetPath,
            diagnosticLogPath,
            diagnosticLogPath is not null);
    }

    public static IReadOnlyList<string> ResolveTargetPaths(string? targetPath, bool allLocalDrives)
    {
        if (!string.IsNullOrWhiteSpace(targetPath))
            return new[] { ResolveTargetPath(targetPath) };

        if (allLocalDrives && OperatingSystem.IsWindows())
        {
            string[] drives = DriveInfo.GetDrives()
                .Where(drive => drive.IsReady && drive.DriveType == DriveType.Fixed)
                .Select(drive => drive.RootDirectory.FullName)
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (drives.Length > 0)
                return drives;
        }

        return new[] { GetDefaultTargetPath() };
    }

    public static string ResolveOutputPathForTarget(string outputPath, string targetPath, int targetCount)
    {
        string fullOutput = Path.GetFullPath(outputPath);
        if (targetCount <= 1)
            return fullOutput;

        string directory = Path.GetDirectoryName(fullOutput) ?? Directory.GetCurrentDirectory();
        string fileName = Path.GetFileName(fullOutput);
        string suffix = GetTargetSuffix(targetPath);

        const string cycloneDxJsonSuffix = ".cdx.json";
        string outputFileName = fileName.EndsWith(cycloneDxJsonSuffix, StringComparison.OrdinalIgnoreCase)
            ? fileName[..^cycloneDxJsonSuffix.Length] + $"-{suffix}" + cycloneDxJsonSuffix
            : Path.GetFileNameWithoutExtension(fileName) + $"-{suffix}" + Path.GetExtension(fileName);

        return Path.Combine(directory, outputFileName);
    }

    public static string GetDefaultTargetPath()
    {
        if (OperatingSystem.IsWindows())
        {
            string? drive = Environment.GetEnvironmentVariable("SystemDrive");
            if (string.IsNullOrWhiteSpace(drive))
                drive = "C:";
            return $"{drive}\\";
        }

        return "/";
    }

    private static string ResolveTargetPath(string? targetPath)
    {
        if (!string.IsNullOrWhiteSpace(targetPath))
        {
            string fullPath = Path.GetFullPath(targetPath);
            if (!File.Exists(fullPath) && !Directory.Exists(fullPath))
                throw new InvalidOperationException($"SBOM target does not exist: {fullPath}");
            return fullPath;
        }

        return GetDefaultTargetPath();
    }

    private static string GetTargetSuffix(string targetPath)
    {
        string? root = Path.GetPathRoot(targetPath);
        string raw = string.IsNullOrWhiteSpace(root) ? targetPath : root;
        string suffix = new string(raw
            .Where(c => char.IsLetterOrDigit(c))
            .ToArray());

        return string.IsNullOrWhiteSpace(suffix) ? "root" : suffix;
    }

    private static string GetSafeHostName()
    {
        string hostName = Environment.MachineName;
        char[] invalidChars = Path.GetInvalidFileNameChars();
        string safe = new(hostName
            .Select(c => invalidChars.Contains(c) ? '_' : c)
            .ToArray());

        return string.IsNullOrWhiteSpace(safe) ? "unknown-host" : safe;
    }

    private static string? WriteDiagnosticsLog(string outputPath, string targetPath, string stdOut, string stdErr)
    {
        if (string.IsNullOrWhiteSpace(stdOut) && string.IsNullOrWhiteSpace(stdErr))
            return null;

        string logPath = outputPath + ".trivy.log";
        var log = new StringBuilder();
        log.AppendLine($"Target: {targetPath}");
        log.AppendLine($"SBOM: {outputPath}");
        log.AppendLine();

        if (!string.IsNullOrWhiteSpace(stdOut))
        {
            log.AppendLine("STDOUT:");
            log.AppendLine(stdOut.TrimEnd());
            log.AppendLine();
        }

        if (!string.IsNullOrWhiteSpace(stdErr))
        {
            log.AppendLine("STDERR:");
            log.AppendLine(stdErr.TrimEnd());
            log.AppendLine();
        }

        File.WriteAllText(logPath, log.ToString());
        return logPath;
    }

    private static string ResolveTrivyPath()
    {
        string executableName = OperatingSystem.IsWindows() ? "trivy.exe" : "trivy";

        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "bin", executableName),
            Path.Combine(Directory.GetCurrentDirectory(), "bin", executableName),
            Path.Combine(AppContext.BaseDirectory, executableName)
        };

        foreach (string candidate in candidates)
        {
            if (File.Exists(candidate))
                return candidate;
        }

        throw new FileNotFoundException(
            $"Trivy executable not found. Expected at SCA_SCANNER/bin/{executableName}. Checked: {string.Join(", ", candidates.Select(Path.GetFullPath))}");
    }
}
