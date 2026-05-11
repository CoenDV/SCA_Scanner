// =============================================================================
//  Wazuh SCA Policy Scanner — C# Implementation
//  Usage:  ./SCAScanner <path/to/policy.yaml>
//          ./SCAScanner -h | --help
// =============================================================================

using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using SCAScanner;

// ── Helper Functions ──────────────────────────────────────────────────────

static SCAPolicy LoadPolicy(string path, IDeserializer deserializer)
{
    string yaml = File.ReadAllText(path);
    return deserializer.Deserialize<SCAPolicy>(yaml);
}

static string GetPlatform() =>
    OperatingSystem.IsWindows() ? "Windows" :
    OperatingSystem.IsMacOS()   ? "macOS"   : "Linux";

// ── Requirements check (silent) ──────────────────────────────────────────────

static bool RequirementsMet(SCAPolicy policy)
{
    if (policy.Requirements is null) return true;
    Check reqCheck = new()
    {
        Id        = 0,
        Title     = policy.Requirements.Title,
        Condition = policy.Requirements.Condition,
        Rules     = policy.Requirements.Rules
    };
    return RuleChecker.EvaluateCheck(reqCheck, policy.Variables).Status == CheckStatus.Passed;
}

// ── Directory Scan ────────────────────────────────────────────────────────────

static int ScanDirectory(string dirPath, IReporter reporter, IDeserializer deserializer)
{
    List<string> files = Directory.GetFiles(dirPath, "*.yml")
        .Concat(Directory.GetFiles(dirPath, "*.yaml"))
        .OrderBy(f => f)
        .ToList();

    if (files.Count == 0)
    {
        reporter.PrintNoPolicesFound(dirPath);
        return 1;
    }

    reporter.PrintDiscoveryHeader(dirPath, files.Count);

    // ── Check requirements for each file ──────────────────────────────────────
    List<string> applicable = new();

    foreach (string file in files)
    {
        string fileName = Path.GetFileName(file);
        SCAPolicy policy;
        try { policy = LoadPolicy(file, deserializer); }
        catch (Exception)
        {
            reporter.PrintRequirementCheckLine(fileName, false, "parse error — skipped");
            continue;
        }

        if (RequirementsMet(policy))
        {
            string note = policy.Requirements is null ? "no requirements" : "requirements met";
            reporter.PrintRequirementCheckLine(fileName, true, note);
            applicable.Add(file);
        }
        else
        {
            reporter.PrintRequirementCheckLine(fileName, false, "requirements not met — skipped");
        }
    }

    if (applicable.Count == 0)
    {
        reporter.PrintError("No applicable policies found for this system.");
        return 1;
    }

    reporter.PrintApplicablePoliciesLine(applicable.Count);

    // ── Run each applicable policy ────────────────────────────────────────────
    int overallFailed = 0;
    for (int i = 0; i < applicable.Count; i++)
    {
        reporter.PrintPolicyExecutionHeader(i + 1, applicable.Count, Path.GetFileName(applicable[i]));
        int result = ScanCommand(applicable[i], reporter, deserializer);
        if (result != 0) overallFailed++;
    }

    reporter.PrintDirectoryScanComplete(applicable.Count, overallFailed);

    return overallFailed > 0 ? 1 : 0;
}

// ── Scan Command ─────────────────────────────────────────────────────────

static int ScanCommand(string policyPath, IReporter reporter, IDeserializer deserializer)
{
    if (!File.Exists(policyPath))
    {
        reporter.PrintError($"policy file not found → {policyPath}");
        return 1;
    }

    SCAPolicy policy;
    try
    {
        policy = LoadPolicy(policyPath, deserializer);
    }
    catch (Exception ex)
    {
        reporter.PrintError($"parsing policy YAML: {ex.Message}");
        return 1;
    }

    reporter.PrintPolicyHeader(policy, GetPlatform());

    // ── Requirements ─────────────────────────────────────────────────────────────

    if (policy.Requirements is not null)
    {
        Check reqCheck = new()
        {
            Id          = 0,
            Title       = policy.Requirements.Title,
            Description = policy.Requirements.Description,
            Condition   = policy.Requirements.Condition,
            Rules       = policy.Requirements.Rules
        };

        CheckResult reqResult = RuleChecker.EvaluateCheck(reqCheck, policy.Variables);
        reporter.PrintRequirementsSection(reqCheck, policy.Variables, reqResult);

        if (reqResult.Status != CheckStatus.Passed)
            return 1;
    }

    // ── Run checks ────────────────────────────────────────────────────────────────

    int totalPassed = 0, totalFailed = 0, totalInvalid = 0;
    List<ScanCheckResult> checkResults = new();

    foreach (Check check in policy.Checks)
    {
        reporter.PrintCheckHeader(check);

        // ── Parse & explain rules before execution ──────────────────────────────
        List<ParsedRule> parsedRules = check.Rules
            .Select(rule => RuleParser.Parse(rule, policy.Variables))
            .ToList();

        reporter.PrintRuleExplanations(parsedRules, check, policy.Variables);

        // ── Execute ──────────────────────────────────────────────────────────────
        CheckResult result = RuleChecker.EvaluateCheck(check, policy.Variables);
        reporter.PrintRuleResults(result.RuleResults);
        reporter.PrintCheckResult(check, result, totalPassed, totalFailed);

        checkResults.Add(new ScanCheckResult
        {
            Id = check.Id,
            Title = check.Title,
            Status = result.Status,
            Reason = result.Reason
        });

        if (result.Status == CheckStatus.Passed)
            totalPassed++;
        else if (result.Status == CheckStatus.Failed)
            totalFailed++;
        else if (result.Status == CheckStatus.Invalid)
            totalInvalid++;
    }

    // ── Summary ───────────────────────────────────────────────────────────────────

    reporter.PrintScanSummary(totalPassed, totalFailed, totalInvalid, checkResults);

    return totalFailed > 0 ? 1 : 0;
}

// ── Main Entry Point ─────────────────────────────────────────────────────────

OutputLevel outputLevel = OutputLevel.Standard;
string? logFile     = null;
string? csvFile     = null;
string? scapSccFile = null;
string? sbomFile    = null;
string? target      = null;

// SFTP configuration
string? sftpHost = null;
int sftpPort = 22;
string? sftpUser = Environment.GetEnvironmentVariable("SFTP_USER");
string? sftpPass = Environment.GetEnvironmentVariable("SFTP_PASS");
string? sftpKey = null;
string? sftpPath = Environment.GetEnvironmentVariable("SFTP_PATH") ?? "/";

// ── Phase 1: Early argument scanning for --write-config and --config ─────────
string? configPath = null;
for (int i = 0; i < args.Length; i++)
{
    if (args[i] == "--write-config")
    {
        // Determine output path for config template
        string writePath = (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
            ? args[++i]
            : "config.yml";

        var tempConsoleReporter = new ConsoleReporter();
        try
        {
            ConfigLoader.WriteTemplate(writePath, tempConsoleReporter);
        }
        catch (Exception ex)
        {
            tempConsoleReporter.PrintError(ex.Message);
            return 1;
        }
        return 0;
    }

    if ((args[i] == "-c" || args[i] == "--config") && i + 1 < args.Length)
    {
        configPath = args[++i];
    }
}

// ── Phase 2: Load configuration file (if it exists) ───────────────────────────
var tempReporter = new ConsoleReporter();
ScannerConfig loadedConfig;
try
{
    loadedConfig = ConfigLoader.LoadConfig(configPath, tempReporter);
}
catch (Exception ex)
{
    tempReporter.PrintError(ex.Message);
    return 1;
}

// Apply loaded config values as defaults for CLI arguments
try
{
    if (loadedConfig.OutputLevel.HasValue)
        outputLevel = loadedConfig.OutputLevel.Value;
    if (loadedConfig.LogFile is not null)
        logFile = loadedConfig.LogFile;
    if (loadedConfig.CsvFile is not null)
        csvFile = loadedConfig.CsvFile;
    if (loadedConfig.ReportFile is not null)
        scapSccFile = loadedConfig.ReportFile;
    if (loadedConfig.SbomFile is not null)
        sbomFile = loadedConfig.SbomFile;
    if (loadedConfig.SftpHost is not null)
        sftpHost = loadedConfig.SftpHost;
    if (loadedConfig.SftpPort.HasValue)
        sftpPort = loadedConfig.SftpPort.Value;
    if (loadedConfig.SftpUser is not null)
        sftpUser = loadedConfig.SftpUser;
    if (loadedConfig.SftpPass is not null)
        sftpPass = loadedConfig.SftpPass;
    if (loadedConfig.SftpKey is not null)
        sftpKey = loadedConfig.SftpKey;
    if (loadedConfig.SftpPath is not null)
        sftpPath = loadedConfig.SftpPath;
}
catch (ArgumentException ex)
{
    tempReporter.PrintError(ex.Message);
    return 1;
}

// ── Phase 3: Parse CLI arguments (overrides config file values) ──────────────
for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "-h":
        case "--help":
            new ConsoleReporter().PrintHelp();
            return 0;
        case "--display-details":
            outputLevel = OutputLevel.Detailed;
            break;
        case "--no-details":
            outputLevel = OutputLevel.Compact;
            break;
        case "-l":
        case "--log":
            if (i + 1 < args.Length)
                logFile = args[++i];
            else
            {
                Console.Error.WriteLine("Error: -l/--log requires a file path argument.");
                return 1;
            }
            break;
        case "--csv":
            if (i + 1 < args.Length)
                csvFile = args[++i];
            else
            {
                Console.Error.WriteLine("Error: --csv requires a file path argument.");
                return 1;
            }
            break;
        case "-r":
        case "--report":
            if (i + 1 < args.Length)
                scapSccFile = args[++i];
            else
            {
                Console.Error.WriteLine("Error: -r/--report requires a file path argument.");
                return 1;
            }
            break;
        case "--sbom-file":
            if (i + 1 < args.Length)
                sbomFile = args[++i];
            else
            {
                Console.Error.WriteLine("Error: --sbom-file requires a file path argument.");
                return 1;
            }
            break;
        case "--sftp":
            if (i + 1 < args.Length)
            {
                string hostPort = args[++i];
                string[] parts = hostPort.Split(':');
                sftpHost = parts[0];
                if (parts.Length > 1 && int.TryParse(parts[1], out int port))
                    sftpPort = port;
            }
            else
            {
                Console.Error.WriteLine("Error: --sftp requires a host[:port] argument.");
                return 1;
            }
            break;
        case "--sftp-user":
            if (i + 1 < args.Length)
                sftpUser = args[++i];
            else
            {
                Console.Error.WriteLine("Error: --sftp-user requires a username argument.");
                return 1;
            }
            break;
        case "--sftp-pass":
            if (i + 1 < args.Length)
                sftpPass = args[++i];
            else
            {
                Console.Error.WriteLine("Error: --sftp-pass requires a password argument.");
                return 1;
            }
            break;
        case "--sftp-key":
            if (i + 1 < args.Length)
                sftpKey = args[++i];
            else
            {
                Console.Error.WriteLine("Error: --sftp-key requires a file path argument.");
                return 1;
            }
            break;
        case "--sftp-path":
            if (i + 1 < args.Length)
                sftpPath = args[++i];
            else
            {
                Console.Error.WriteLine("Error: --sftp-path requires a path argument.");
                return 1;
            }
            break;
        case "-c":
        case "--config":
            // Already handled in Phase 1, just skip here
            if (i + 1 < args.Length) i++;
            break;
        case "--write-config":
            // Already handled in Phase 1, just skip here
            if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                i++;
            break;
        default:
            if (target is null)
                target = args[i];
            else
            {
                Console.Error.WriteLine($"Error: unexpected argument '{args[i]}'.");
                return 1;
            }
            break;
    }
}

if (target is null)
{
    new ConsoleReporter().PrintHelp();
    return 0;
}

ConsoleReporter consoleReporter = new(outputLevel);
// Use object list so non-IReporter sub-reporters (e.g. CsvReporter) can be included
List<object> reporters = [consoleReporter];
if (logFile is not null) reporters.Add(new FileReporter(logFile));
if (csvFile     is not null) reporters.Add(new CsvReporter(csvFile));
if (scapSccFile is not null) reporters.Add(new AdvancedReporter(scapSccFile));
IReporter reporter = reporters.Count > 1
    ? new CompositeReporter([.. reporters])
    : consoleReporter;

IDeserializer deserializer = new DeserializerBuilder()
    .WithNamingConvention(UnderscoredNamingConvention.Instance)
    .IgnoreUnmatchedProperties()
    .Build();

int exitCode = 0;
string? generatedSbomPath = null;

try
{
    if (Directory.Exists(target))
        exitCode = ScanDirectory(target, reporter, deserializer);
    else
        exitCode = ScanCommand(target, reporter, deserializer);

    var sbomGenerator = new TrivySbomGenerator();
    string plannedSbomPath = string.IsNullOrWhiteSpace(sbomFile)
        ? sbomGenerator.ResolveDefaultOutputPath()
        : sbomFile;

    consoleReporter.PrintInfo($"Generating SBOM with Trivy (target: {(OperatingSystem.IsWindows() ? "system drive root" : "/")})...");
    consoleReporter.PrintInfo($"SBOM output file: {Path.GetFullPath(plannedSbomPath)}");

    generatedSbomPath = sbomGenerator.GenerateSbom(plannedSbomPath);
    consoleReporter.PrintInfo($"SBOM generation completed: {generatedSbomPath}");
}
catch (Exception ex)
{
    consoleReporter.PrintError($"SBOM generation failed: {ex.Message}");
    exitCode = 1;
}
finally
{
    if (reporter is IDisposable d) d.Dispose();

    // Upload files to SFTP server if configured
    if (sftpHost is not null)
    {
        var sftpConfig = new SftpConfig
        {
            Host = sftpHost,
            Port = sftpPort,
            User = sftpUser,
            Password = sftpPass,
            KeyPath = sftpKey,
            RemotePath = sftpPath
        };

        var filesToUpload = new List<string>();
        if (logFile is not null && File.Exists(logFile)) filesToUpload.Add(logFile);
        if (csvFile is not null && File.Exists(csvFile)) filesToUpload.Add(csvFile);
        if (scapSccFile is not null && File.Exists(scapSccFile)) filesToUpload.Add(scapSccFile);
        if (generatedSbomPath is not null && File.Exists(generatedSbomPath)) filesToUpload.Add(generatedSbomPath);

        if (filesToUpload.Any())
        {
            try
            {
                var uploader = new SftpUploader();
                uploader.UploadFilesAsync(sftpConfig, filesToUpload, consoleReporter).GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                consoleReporter.PrintError($"SFTP upload failed: {ex.Message}");
                exitCode = 1;
            }
        }
    }
}

return exitCode;
