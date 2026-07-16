# SCA_Scanner

Standalone tool to scan a system Compliance status with Security Configuration Assessment (SCA) in YAML format.

- Wazuh explains how SCA works [here](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/how-it-works.html).
- And provides CIS benchmarks [here](https://github.com/wazuh/wazuh/tree/main/ruleset/sca).

## Get started
Download the binary from [releases](https://github.com/J0113/SCA_Scanner/releases/) and run privileged.
```
# ./SCAScanner -h

USAGE:
  SCAScanner [options] <path/to/policy.yaml>   Run all checks from a policy file
  SCAScanner [options] <path/to/dir>           Scan all .yml/.yaml policies in a directory,
                                               skipping those whose requirements don't apply

OPTIONS:
  --display-details           Show full rule details in console output
  --no-details                Show only header and summary (no requirements or rules)
  --output-dir <dir>          Root for default files (default: REPORTS_DIR or platform standard)
  -l, --log <file>            Write detailed output to a log file
  --csv <file>                Write scan results as CSV (one row per check)
  -r, --report <file>         Write scan results in SCAP-SCC log format
  --sbom-file <file>          Write Trivy CycloneDX SBOM to file
  --sbom-target <path>        Set Trivy SBOM target path (default: system drive root on Windows, / elsewhere)
  --sbom-all-drives           On Windows, write one SBOM per ready fixed local drive
  --sbom-timeout <duration>   Set Trivy timeout (e.g., 5m, 30s, 1h, none)
  --sbom-skip-dir <list>      Comma-separated directories to skip in SBOM scan
  --sbom-skip-file <list>     Comma-separated files to skip in SBOM scan

CONFIG FILE OPTIONS:
  -c, --config <path>         Load configuration from YAML file
  --write-config [path]       Generate a template config file (default: config.yml)
                              Use with path to write to custom location

  -h, --help                  Show this help message

NOTES:
  - Config file is optional. By default, app looks for 'config.yml' in working dir
  - CLI arguments always override config file values
  - Default reports are written to REPORTS_DIR when set
  - Otherwise reports use /var/lib/platform-scanning on Linux
  - On macOS the standard report directory is /Library/Application Support/platform-scanning
  - On Windows the standard report directory is C:\ProgramData\platform-scanning
  - SBOM generation runs on every scan using Trivy from 'SCA_SCANNER/bin'
  - SBOM output lists detected software components, not every file on disk
  - Successful Trivy warnings are saved next to the SBOM as *.trivy.log
  - Trivy timeout defaults to 5m; use --sbom-timeout none to disable

EXAMPLES:
  SCAScanner Policies/sample_policy.yaml
  SCAScanner --display-details Policies/sample_policy.yaml
  SCAScanner --write-config
  SCAScanner --config custom.yml --no-details --csv report.csv Policies/
  SCAScanner --sbom-file host-sbom.cdx.json Policies/sample_policy.yaml
  SCAScanner --sbom-all-drives --sbom-file host-sbom.cdx.json Policies/sample_policy.yaml
```

## Hardening and SBOM workflow plan

1. Keep policy files in `Policies/`, grouped by operating system and benchmark family. Use each policy's `requirements` block to make the directory scan self-selecting, so one command can safely run against mixed Windows, Linux, and macOS policy sets.

2. Run the scanner against the policy directory, not one file, for routine hardening checks:
   ```powershell
   .\SCAScanner.exe Policies\
   ```
   The scanner writes hardening evidence and the SBOM to the standard report directory. Set `REPORTS_DIR` or pass `--output-dir` to override it.

3. Use explicit output roots for campaigns, baselines, or change windows:
   ```powershell
   .\SCAScanner.exe --output-dir .\output\baseline-2026-05 Policies\
   ```

4. Use `--sbom-all-drives` on Windows hosts where software may live outside the system drive. This creates one SBOM per ready fixed local drive under the host's SBOM folder.

5. Review hardening results and SBOM diagnostics together. If Trivy reports warnings on a successful SBOM run, the scanner writes a neighboring `*.trivy.log` file so inaccessible paths or scanner limitations are visible.

6. Treat the SBOM as a detected software inventory, not a full filesystem manifest. Use the hardening reports for configuration evidence and the SBOM for package/component evidence.

## Windows VM workflow
Use the Windows release bundle together with `Invoke-ScannerBundle.ps1` for a simple deploy-and-cleanup flow.

1. Download or copy `publish/release/SCAScanner-win-x64.exe.zip` to the VM and extract it to a working folder.
2. Run the bundled wrapper from that folder:
  ```powershell
  .\Invoke-ScannerBundle.ps1 -PolicyPath Policies\cis_win2022.yml
  ```
3. To scan a different policy, change `-PolicyPath` to a file or directory inside the bundle. Results are written directly into the bundle-local `results` folder with timestamped names that include the policy and host name. Use `-RunName` only if you want to change the filename prefix.
4. If you want to keep the extracted bundle root when you passed `-BundleZip`, add `-KeepStagingRoot`.
5. If you want to scan every fixed local drive as part of the SBOM step, pass `-AllDrives`.
6. The archive remains for collection, and the extracted bundle copy is removed automatically unless `-KeepStagingRoot` is used.



## TODO:
- [X] Runs on Windows 
- [X] Runs on MacOS
- [X] Runs on Linux
- [X] Log to logfile
- [X] Output to file (in multiple formats, CSV, JSON and TEXT)
- [X] Variable support
- [X] Support check conditions [(All, any, none)](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html#condition)
- [X] Rule type ['Directory'](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html#rules)
- [X] Rule type ['Process'](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html#rules)
- [X] Rule type ['Commands'](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html#rules)
- [X] Rule type ['Registry (Windows Only)'](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html#rules)
- [X] Support all [Content comparison operators](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html#id8)
- [X] Support all [Numeric comparison operators](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html#id9)
- [X] Pass all [examples](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html#examples)
