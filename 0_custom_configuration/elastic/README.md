# Elastic Defend profiles

Two Sysmon profiles for hosts that also run Elastic Defend:

| Profile | Include list | Collection goal |
| --- | --- | --- |
| Research | `research.txt` | Every event except Elastic Agent and Elastic Defend noise. For short, controlled research sessions. |
| Complement | `complement.txt` | Only telemetry that Elastic Defend did not record in a lab comparison, plus evidence of Elastic Defend being stopped or tampered with. |

The selections come from a Detection Lab comparison on September 30, 2026, revalidated on October 2, 2026. It ran Elastic Defend 9.4 with and without Sysmon on two Windows Server hosts. The figures below are one day of one host's workload, mostly administrative activity over SSH. Treat them as a starting point, not a production baseline.

## Generate

Run the helper from any directory:

```bash
./0_custom_configuration/elastic/generate-sysmonconfig-elastic.sh
```

It writes `sysmonconfig-elastic-research.xml` and `sysmonconfig-elastic-complement.xml` for Sysmon 15.21 to `outputs/`, which Git ignores. Pass another directory as the first argument. The helper finds `sysmon-modular` the same way as the [MDE augment helper](../README.md#mde-augment-configuration). Unlike that helper, it treats merge warnings as errors, so a mistyped list entry fails the build instead of silently dropping a module.

## Layout

Modules about the Elastic product itself live in the numbered directories next to the other vendor modules. The balanced release profile uses them too:

| Module | Change | Lab evidence |
| --- | --- | --- |
| `3_network_connection_initiated/exclude_elastic.xml` | Adds the Agent collector and Elastic Defend | The collector made 8,239 of 10,213 Event 3 records |
| `10_process_access/exclude_elastic.xml` | Adds the Agent collector and Elastic Defend | 3,053,636 and 637,803 Event 10 records. The existing rule only covered `metricbeat.exe` |
| `12_13_14_registry_event/exclude_elastic.xml` | New | 18,435 CreateKey events from Elastic Defend |
| `17_18_pipe_event/exclude_elastic.xml` | New | Pipes from Elastic Defend and the collector |
| `17_18_pipe_event/exclude_openssh.xml` | New | 40,442 of 52,285 pipe records were OpenSSH `\W32PosixPipe.*` pipes |
| `25_process_tampering/exclude_elastic.xml` | New | Five of the seven Event 25 records were benign Elastic Agent image replacements |
| `5_process_ended/include_security_process_termination.xml` | Adds `elastic-endpoint.exe` and `elastic-agent.exe` | Sysmon recorded Elastic Defend's crash and restart at 13:13 |
| `11_file_create/include_elastic_sensor_file_tampering.xml`, `12_13_14_registry_event/include_elastic_service_tampering.xml`, `26_file_delete_detected/include_elastic_sensor_file_deletion.xml` | New | Tamper evidence, following the MDE sensor modules |

The Agent collector runs from a versioned folder such as `C:\Program Files\Elastic\Agent\data\elastic-agent-9.4.4-baed89\components\`, so the modules match it with an anchored `begin with` and `end with` pair.

Modules that express a profile decision live in `modules/` here. The merger only discovers XML directly inside numbered directories, including `0_custom_configuration/`, so files in `modules/` never reach the release builds. CI's `validate --all-xml` still checks them.

`modules/research_base.xml` and `modules/complement_base.xml` are switchboards, with one rule group per event. An `onmatch="exclude"` filter logs the event in full, apart from exclusions selected elsewhere. An empty `onmatch="include"` filter switches it off. A single include rule for a logged-in-full event would turn it into an allow-list, so the lists never select include modules for those events.

## Research profile

`research_base.xml` reproduces the repository's former `sysmonconfig-research.xml`, removed in `0cefc18`, as rule groups. It makes three changes:

- It drops the `powershell.exe` RegistryEvent exclusion, which hid every PowerShell registry change. That day, Elastic Defend recorded 641 and 552 PowerShell registry modifications on the two lab hosts, and Sysmon recorded none.
- FileBlockExecutable and FileBlockShredding have empty include filters, so nothing is blocked, as in the lab's derivative.
- It logs FileExecutableDetected (29) on Sysmon 15.

On the lab workload, Elastic Agent and Elastic Defend produced about 74% of the 5,038,347 indexed records; the collector alone produced 3,053,636. About 1.3 million would remain over 8.5 hours: mostly Event 7 (545,022, largely PowerShell, sshd, and csc driven by Ansible) and Event 10 from `wmiprvse.exe` and `svchost.exe` (about 460,000), which the data does not attribute to Elastic. The earlier profile saturated a 2-vCPU host and caused gaps in Elastic Defend's own telemetry, so run this one on hosts with headroom and only as long as needed.

Event 24 is logged, and Sysmon archives clipboard contents. Archiving needs a working `ArchiveDirectory`. On the lab hosts Sysmon is installed in `C:\sysmon`, which clashes with the template's `Sysmon` archive directory and disables archiving.

## Complement profile

| Event | Collection | Lab evidence |
| --- | --- | --- |
| 2 | Everything, minus vendor noise | No timestamp-change record in Elastic Defend on either host; 91 records all day |
| 5 | Security tools stopping, including Elastic | Sysmon recorded Elastic Defend's crash and restart |
| 8 | Everything, minus system sources | No thread-creation event in Elastic Defend; 8 records all day |
| 9 | Everything | No raw-device record in Elastic Defend; 178 records all day |
| 10 | LSASS access only (provisional) | No credential-access test was run |
| 11 | Writes into the Elastic folders by other processes | Tamper evidence |
| 12–14 | Deletions and renames of keys of interest; Elastic and Sysmon service tampering | Elastic Defend recorded only modification and query actions all day |
| 15 | Selected file types | Elastic Defend saw the alternate data stream, but none of its 93,070 file events carried a hash |
| 17/18 | All named pipes, minus vendor noise | No pipe telemetry in Elastic Defend; 4,475 records a day after excluding OpenSSH and anonymous pipes |
| 19–21 | Everything | Elastic Defend recorded the registration API call but no deletion |
| 25 | Everything, minus vendor noise | Seven records all day, five from Elastic Agent |
| 26 | Selected locations and the Elastic folders | The same hash gap |
| 29 | Selected locations (provisional) | The same hash gap; not tested |
| 3 | Optional: inbound remote-access ports | Elastic Defend reported repeated inbound connections once: two `sshd.exe` records against Sysmon's 1,444 |
| 1, 6, 7, 22, 23, 24, 27, 28 | Off | 1 and 22 overlapped with Elastic Defend; 6 was not tested; 7 is noisy and was not tested against malicious DLLs; 23, 27, and 28 archive or block files; 24 archives clipboard contents |

`complement.txt` lists the upstream modules this profile leaves out and why. In short, it skips:

- Exclusions that match a process name anywhere on disk, or a pipe name alone.
- `17_18_pipe_event/exclude_windows_generic.xml`, which drops `\srvsvc`, `\wkssvc`, `\lsass`, `\winreg`, and `\spoolss`.
- `10_process_access/exclude_lsass_noise.xml`, which drops `taskmgr.exe` by name.

## Open items

- Load each profile on a lab host with `Sysmon64.exe -c <file>`, then run `Sysmon64.exe -c` to print the active rules. Both profiles rely on several rule groups per event and on empty filters.
- Measure the complement in a rerun of the Atomic tests and the named-pipe test on a host larger than 2 vCPUs. Track Elastic Defend's 15-second gaps, its `log_on` per 4624 ratio, and the Agent's `Record ID gap detected` warnings.
- Check the collector's `GrantedAccess` values. If they are essentially all `0x1000`, as its 24,377 LSASS accesses were, limit the Event 10 exclusion to that mask.
- Confirm the Elastic service and driver key names on a host. `include_elastic_service_tampering.xml` matches every service whose name starts with `Elastic`.
- Measure `include_deletions_of_interest.xml`. The lab data has deletion counts by process but not by key.
- Expect PowerShell's `__PSScriptPolicyTest_*` files and Add-Type compiler output in the user Temp folder to match the user-writable-folder modules for events 26 and 29. Add exclusions if the rerun confirms the volume.
- Event 5 also records Elastic Defend's short-lived helper processes (103 on the lab host) and any `elastic-agent.exe` command-line use.
- Test the provisional rows: credential access (10), unsigned DLL loads (7), and executable drops (29).
- Add both profiles to the release workflow.
