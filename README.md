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
  -l, --log <file>            Write detailed output to a log file
  --csv <file>                Write scan results as CSV (one row per check)
  -r, --report <file>         Write scan results in SCAP-SCC log format
  --sbom-file <file>          Write Trivy CycloneDX SBOM to file

SFTP UPLOAD OPTIONS:
  --sftp <host[:port]>        Upload generated files to SFTP server
  --sftp-user <user>          SFTP username (env: SFTP_USER)
  --sftp-pass <pass>          SFTP password (env: SFTP_PASS) - ignored if using key auth
  --sftp-key <path>           SSH private key file path for key-based authentication
  --sftp-path <path>          Remote directory path (env: SFTP_PATH, default: /)

CONFIG FILE OPTIONS:
  -c, --config <path>         Load configuration from YAML file
  --write-config [path]       Generate a template config file (default: config.yml)
                              Use with path to write to custom location

  -h, --help                  Show this help message

NOTES:
  - Config file is optional. By default, app looks for 'config.yml' in working dir
  - CLI arguments always override config file values
  - SBOM generation runs on every scan using Trivy from 'SCA_SCANNER/bin'

EXAMPLES:
  SCAScanner Policies/sample_policy.yaml
  SCAScanner --display-details Policies/sample_policy.yaml
  SCAScanner --write-config
  SCAScanner --config custom.yml --no-details --csv report.csv Policies/
  SCAScanner --sbom-file host-sbom.cdx.json Policies/sample_policy.yaml
```



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
