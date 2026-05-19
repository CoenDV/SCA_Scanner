using System.Collections.Generic;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace SCAScanner;

/// <summary>
/// Configuration object for SCA Scanner settings, deserialized from YAML config files.
/// All properties are optional; null values indicate no override from config file.
/// </summary>
public class ScannerConfig
{
    // ── Display Settings ──────────────────────────────────────────────────

    /// <summary>Output verbosity level: "standard", "detailed", or "compact".</summary>
    [YamlMember(Alias = "output_level")]
    public string? OutputLevelString { get; set; }

    /// <summary>Parsed OutputLevel from output_level string.</summary>
    [YamlIgnore]
    public SCAScanner.OutputLevel? OutputLevel => ParseOutputLevel(OutputLevelString);

    /// <summary>Root directory for default scanner artifacts.</summary>
    [YamlMember(Alias = "output_dir")]
    public string? OutputDir { get; set; }

    // ── Report File Outputs ───────────────────────────────────────────────

    /// <summary>Path to log file for detailed output.</summary>
    [YamlMember(Alias = "log_file")]
    public string? LogFile { get; set; }

    /// <summary>Path to CSV report file.</summary>
    [YamlMember(Alias = "csv_file")]
    public string? CsvFile { get; set; }

    /// <summary>Path to SCAP-SCC report file.</summary>
    [YamlMember(Alias = "report_file")]
    public string? ReportFile { get; set; }

    /// <summary>Path to SBOM output file (CycloneDX JSON).</summary>
    [YamlMember(Alias = "sbom_file")]
    public string? SbomFile { get; set; }

    /// <summary>Target path for Trivy SBOM generation.</summary>
    [YamlMember(Alias = "sbom_target")]
    public string? SbomTarget { get; set; }

    /// <summary>Generate one SBOM per ready fixed local drive on Windows.</summary>
    [YamlMember(Alias = "sbom_all_drives")]
    public bool? SbomAllDrives { get; set; }

    /// <summary>Trivy timeout (e.g. "5m", "30s", "1h").</summary>
    [YamlMember(Alias = "sbom_timeout")]
    public string? SbomTimeout { get; set; }

    /// <summary>Directories to skip during SBOM generation.</summary>
    [YamlMember(Alias = "sbom_skip_dirs")]
    public List<string>? SbomSkipDirs { get; set; }

    /// <summary>Files to skip during SBOM generation.</summary>
    [YamlMember(Alias = "sbom_skip_files")]
    public List<string>? SbomSkipFiles { get; set; }

    // ── SFTP Settings ─────────────────────────────────────────────────────

    /// <summary>SFTP server hostname or IP address.</summary>
    [YamlMember(Alias = "sftp_host")]
    public string? SftpHost { get; set; }

    /// <summary>SFTP server port (default: 22).</summary>
    [YamlMember(Alias = "sftp_port")]
    public int? SftpPort { get; set; }

    /// <summary>SFTP username.</summary>
    [YamlMember(Alias = "sftp_user")]
    public string? SftpUser { get; set; }

    /// <summary>SFTP password (ignored if SSH key is provided).</summary>
    [YamlMember(Alias = "sftp_pass")]
    public string? SftpPass { get; set; }

    /// <summary>Path to SSH private key file for key-based authentication.</summary>
    [YamlMember(Alias = "sftp_key")]
    public string? SftpKey { get; set; }

    /// <summary>Remote directory path for SFTP uploads (default: "/").</summary>
    [YamlMember(Alias = "sftp_path")]
    public string? SftpPath { get; set; }

    /// <summary>
    /// Creates a default (empty) config object.
    /// </summary>
    public static ScannerConfig CreateDefault() => new();

    /// <summary>
    /// Loads configuration from a YAML file. Returns empty config if file doesn't exist.
    /// </summary>
    /// <param name="path">Path to YAML config file.</param>
    /// <returns>Loaded config or empty config if file not found.</returns>
    /// <exception cref="InvalidOperationException">If YAML deserialization fails.</exception>
    public static ScannerConfig LoadFromFile(string path)
    {
        if (!File.Exists(path))
            return CreateDefault();

        try
        {
            string yaml = File.ReadAllText(path);
            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(UnderscoredNamingConvention.Instance)
                .IgnoreUnmatchedProperties()
                .Build();

            return deserializer.Deserialize<ScannerConfig>(yaml) ?? CreateDefault();
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to parse config file '{path}': {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Writes a template configuration file with all available options and comments.
    /// </summary>
    /// <param name="path">Path where to write the template file.</param>
    public static void WriteTemplate(string path)
    {
        string template = @"# SCA Scanner Configuration File
# Uncomment and modify values as needed
# All values are optional; CLI arguments always override config file settings

# Display Settings
# output_level can be: standard | detailed | compact
# output_level: standard
# output_dir: C:\ProgramData\platform-scanning

# Report File Outputs
# Paths can be relative or absolute. If omitted, reports are written to REPORTS_DIR
# or the platform standard report directory.
# log_file: scan-results.log
# csv_file: scan-results.csv
# report_file: scan-results.txt
# sbom_file: scan-results.json
# sbom_target: C:\
# sbom_all_drives: false
# sbom_timeout: 5m
# sbom_skip_dirs:
#   - C:\Windows\WinSxS
#   - C:\Windows\SoftwareDistribution
# sbom_skip_files:
#   - C:\pagefile.sys

# SFTP Upload Settings
# sftp_host: sftp.example.com      # Hostname or IP address
# sftp_port: 22                     # Default is 22
# sftp_user: username               # Can also use env var SFTP_USER
# sftp_pass: password               # Can also use env var SFTP_PASS
# sftp_key: /path/to/private/key    # For SSH key-based authentication
# sftp_path: /remote/reports        # Can also use env var SFTP_PATH
";

        try
        {
            File.WriteAllText(path, template);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to write config template to '{path}': {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Parses output level string to OutputLevel enum.
    /// </summary>
    private static SCAScanner.OutputLevel? ParseOutputLevel(string? level)
    {
        if (level is null)
            return null;

        return level.ToLower() switch
        {
            "standard" => SCAScanner.OutputLevel.Standard,
            "detailed" => SCAScanner.OutputLevel.Detailed,
            "compact" => SCAScanner.OutputLevel.Compact,
            _ => throw new ArgumentException($"Invalid output_level in config: '{level}'. Must be one of: standard, detailed, compact")
        };
    }
}
