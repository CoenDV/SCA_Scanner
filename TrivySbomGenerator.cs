namespace SCAScanner;

using System.Diagnostics;

public sealed class TrivySbomGenerator
{
    public string ResolveDefaultOutputPath()
    {
        string timestamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
        return Path.Combine(Directory.GetCurrentDirectory(), $"sbom-{timestamp}.cdx.json");
    }

    public string GenerateSbom(string? outputPath)
    {
        string trivyPath = ResolveTrivyPath();
        string finalOutput = string.IsNullOrWhiteSpace(outputPath) ? ResolveDefaultOutputPath() : outputPath;
        string fullOutput = Path.GetFullPath(finalOutput);

        string? outputDir = Path.GetDirectoryName(fullOutput);
        if (!string.IsNullOrWhiteSpace(outputDir))
            Directory.CreateDirectory(outputDir);

        string targetPath = ResolveSystemRootTarget();

        using var process = Process.Start(new ProcessStartInfo
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
                "--output", fullOutput,
                targetPath
            }
        });

        if (process is null)
            throw new InvalidOperationException("Failed to start Trivy process.");

        string stdOut = process.StandardOutput.ReadToEnd();
        string stdErr = process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            string detail = string.IsNullOrWhiteSpace(stdErr) ? stdOut : stdErr;
            throw new InvalidOperationException($"Trivy exited with code {process.ExitCode}: {detail.Trim()}");
        }

        if (!File.Exists(fullOutput))
            throw new InvalidOperationException($"Trivy completed but SBOM file was not created: {fullOutput}");

        return fullOutput;
    }

    private static string ResolveSystemRootTarget()
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
