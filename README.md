# chv-ServiceAccountPrivilegeChecker
Analyzes service account configurations across various platforms (e.g., Windows, Linux) to identify excessive privileges and potential privilege escalation paths. Reports service accounts with permissions beyond the minimum required for their functions. - Focused on Automates the verification of system configurations against defined security baselines (CIS benchmarks, DISA STIGs). Reads configuration files (YAML, JSON) and validates them against schemas that define acceptable security settings. Provides reports indicating deviations and recommended remediations. Focuses on static configuration analysis, not runtime monitoring.

## Install
`git clone https://github.com/ShadowStrikeHQ/chv-serviceaccountprivilegechecker`

## Usage
`./chv-serviceaccountprivilegechecker [params]`

## Parameters
- `-h`: Show help message and exit
- `-l`: Set the logging level.
- `-o`: No description provided

## License
Copyright (c) ShadowStrikeHQ
