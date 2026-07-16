# SCA Scanner

## What this repo does
This is a .NET 10 console app that evaluates a machine against Wazuh SCA YAML policies. It can scan a single policy file or a directory of policies, skip policies whose `requirements` block does not match the current host, and write multiple output formats for the same run.

The scanner supports Windows, macOS, and Linux. It evaluates file, directory, process, command, and registry rules, applies `all` / `any` / `none` conditions, and emits console output plus optional log, CSV, SCAP-SCC, SBOM, and SFTP-uploaded artifacts.

## How it works
1. `Program.cs` handles startup, argument parsing, config loading, report setup, policy execution, SBOM generation, and optional upload.
2. Config loading happens before normal CLI parsing. A `config.yml` in the working directory is used if present, and CLI arguments override config values.
3. `--write-config` exits early after creating a template config file.
4. If the target path is a directory, the scanner loads all `.yml` and `.yaml` files, checks each policy's `requirements`, and only runs the applicable ones.
5. For a single policy file, the scanner prints the policy header, evaluates `requirements` if present, then runs each `check` in order.
6. After the policy scan, the app always tries to generate a Trivy CycloneDX SBOM. The SBOM target defaults to the host root unless `--sbom-target` or `--sbom-all-drives` is used.
7. If the app is running from a bundle that contains `Policies/`, the default output folder becomes a local `results/` directory next to the bundle contents, and the wrapper writes flat timestamped files directly into that folder.
8. If SFTP is configured, the scanner uploads the generated artifacts after local output is written.

## Main files
| File | Purpose |
|------|---------|
| `Program.cs` | Entry point and orchestration for config, scanning, SBOM generation, and upload |
| `Models.cs` | YAML-backed policy models, enums, and scan result types |
| `RuleParser.cs` | Parses Wazuh rule strings into structured rules |
| `RuleChecker.cs` | Executes rule evaluation and condition logic |
| `ScannerConfig.cs` | YAML config model, template writer, and config loader helpers |
| `ConfigLoader.cs` | Loads `config.yml` or an explicit config file and writes templates |
| `TrivySbomGenerator.cs` | Wraps Trivy execution and SBOM output generation |
| `SftpConfig.cs` / `SftpUploader.cs` | SFTP configuration and artifact upload |
| `IReporter.cs` | Reporter contracts used by the output pipeline |
| `ConsoleReporter.cs`, `FileReporter.cs`, `CsvReporter.cs`, `AdvancedReporter.cs`, `CompositeReporter.cs` | Console, log, CSV, SCAP-SCC, and fan-out reporting |
| `StringUtils.cs` | Small shared string helpers |

## Build and run
```bash
dotnet build SCAScanner.csproj
dotnet run --project SCAScanner.csproj [policy.yaml | policy_dir]
```

Common options:
`--display-details`, `--no-details`, `-l|--log`, `--csv`, `-r|--report`, `--output-dir`, `--sbom-file`, `--sbom-target`, `--sbom-all-drives`, `--sbom-timeout`, `--sbom-skip-dir`, `--sbom-skip-file`, `--sftp`, `--sftp-user`, `--sftp-pass`, `--sftp-key`, `--sftp-path`, `-c|--config`, `--write-config`, `-h|--help`.

## Output behavior
Default artifacts are written under `REPORTS_DIR` when set, otherwise to the platform standard directory:
Windows: `C:\ProgramData\platform-scanning`
macOS: `/Library/Application Support/platform-scanning`
Linux: `/var/lib/platform-scanning`

If no explicit file names are supplied, the app creates host-specific defaults: `hardening-<host>.log`, `hardening-<host>.csv`, `hardening-<host>.txt`, and `sbom-<host>.cdx.json`. There is no timestamp — re-running a scan on the same host overwrites that host's previous files. When an SBOM run covers multiple drives, each target's file gets a dot-separated drive suffix before the CycloneDX extension (e.g. `sbom-<host>.C.cdx.json`, `sbom-<host>.D.cdx.json`), and any Trivy diagnostics are written alongside as `sbom-<host>.C.trivy.log`. The bundle wrapper (`Invoke-ScannerBundle.ps1`) uses this same `hardening-<host>.*` / `sbom-<host>.cdx.json` convention, keyed only on `$env:COMPUTERNAME`.

## Policy format summary
The scanner follows the Wazuh SCA style:
`f:` file checks, `d:` directory checks, `p:` process checks, `c:` command output checks, and `r:` registry checks on Windows.

Rules support literal matches, regex matches, numeric comparisons, negation, and combined `&&` matches. Check conditions are `all`, `any`, or `none`.

## Implementation notes
- `CompositeReporter` fans out to the console, log, CSV, and SCAP-SCC reporters.
- `ScannerConfig` is optional and only supplies defaults; CLI always wins.
- When the executable is run from a published bundle that includes `Policies/`, the default output root resolves to a sibling `results/` folder instead of the system report directory, and the generic wrapper keeps the output flat instead of nesting a per-run folder.
- Trivy is resolved from `bin/trivy` or `bin/trivy.exe` near the app.
- SBOM generation writes a neighboring `.trivy.log` file when Trivy emits diagnostics.
- The default `--sbom-timeout` is 30m (applies per SBOM target, so `--sbom-all-drives` can take a multiple of that). On Windows, unless `--sbom-skip-dir`/`--sbom-skip-file` (or the config equivalents) are set, the scanner defaults to skipping `Windows/WinSxS`, `Windows/SoftwareDistribution`, `Windows/Temp`, `System Volume Information`, `$Recycle.Bin`, `ProgramData/Microsoft/Windows Defender`, and `pagefile.sys`/`hiberfil.sys`/`swapfile.sys` to keep full-drive scans reasonable.
- Directory scans only execute policies whose `requirements` block passes on the current host.
- The process exits nonzero only when it fails to run at all: bad CLI arguments/config, a policy file that's missing or unparsable, a policy directory with no `.yml`/`.yaml` files, or a directory scan where no policy's `requirements` match the host. Failed checks, unmet requirements on a directly-targeted policy, SBOM/Trivy generation problems, and SFTP upload failures are reported (console/log/results) but do not affect the exit code.

## When changing code
If you need to change scan behavior, start in `Program.cs`, `RuleChecker.cs`, and `RuleParser.cs` before touching the reporters. If you need to change output shape, work in the reporter classes first. If you need to change config precedence or defaults, update `ScannerConfig.cs` and `ConfigLoader.cs` together.
