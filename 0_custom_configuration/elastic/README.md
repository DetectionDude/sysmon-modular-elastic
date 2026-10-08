# Elastic Defend profiles

Two Sysmon profiles for hosts that also run Elastic Defend:

| Profile | Include list | Collection goal |
| --- | --- | --- |
| Research | `research.txt` | Every event except Elastic Agent and Elastic Defend noise. For short, controlled research sessions. |
| Complement | `complement.txt` | Only telemetry that Elastic Defend did not record in a lab comparison, plus evidence of Elastic Defend being stopped or tampered with. |

The selections come from a Detection Lab comparison on September 30, 2026, revalidated on October 2, 2026. It ran Elastic Defend 9.4 with and without Sysmon on two Windows Server hosts. The figures below are one day of one host's workload, mostly administrative activity over SSH. Treat them as a starting point, not a production baseline.

A three-host test on October 7, 2026, with a Defend-only control on 4-vCPU hosts, replayed the same behaviors against both profiles. Its indexed data confirms that the filters behave as designed on Sysmon 15.22. It lost no records and found no gaps in Elastic Defend's telemetry.

## Generate

Run the helper from any directory:

```bash
./0_custom_configuration/elastic/generate-sysmonconfig-elastic.sh
```

It writes `sysmonconfig-elastic-research.xml` and `sysmonconfig-elastic-complement.xml` for Sysmon 15.21 to `outputs/`, which Git ignores. Pass another directory as the first argument. CI runs the same helper on every push to the `elastic` branch and publishes both files as an `elastic-<commit>` GitHub release. The helper finds `sysmon-modular` the same way as the [MDE augment helper](../README.md#mde-augment-configuration). Unlike that helper, it treats merge warnings as errors, so a mistyped list entry fails the build instead of silently dropping a module.

## Layout

Modules about the Elastic product itself live in the numbered directories next to the other vendor modules. The balanced release profile uses them too:

| Module | Change | Lab evidence |
| --- | --- | --- |
| `3_network_connection_initiated/exclude_elastic.xml` | Adds the Agent collector and Elastic Defend | The collector made 8,239 of 10,213 Event 3 records |
| `10_process_access/exclude_elastic.xml` | Adds the Agent collector and Elastic Defend | 3,053,636 and 637,803 Event 10 records. The existing rule only covered `metricbeat.exe`. Nearly all of Elastic Defend's records came before the lab profile's identical rule took effect at 07:25:30; afterward it was no longer among the top 15 sources |
| `12_13_14_registry_event/exclude_elastic.xml` | New. Excludes only Elastic Defend's CreateKey events | All 18,435 of Elastic Defend's Event 12 records were CreateKey |
| `17_18_pipe_event/exclude_elastic.xml` | New | Pipes from Elastic Defend and the collector |
| `17_18_pipe_event/exclude_openssh.xml` | New | 40,442 of 52,285 pipe records were OpenSSH `\W32PosixPipe.*` pipes |
| `5_process_ended/include_security_process_termination.xml` | Adds `elastic-endpoint.exe`, `elastic-agent.exe`, the collector `elastic-otel-collector.exe`, `endpoint-security.exe`, and the 8.x collector `agentbeat.exe`. Pairs with the Event 1 module below | Sysmon recorded Elastic Defend's crash at 13:13 as an Event 5. The collector ships the Sysmon and Windows logs, so stopping it blinds the SIEM while Elastic Defend keeps running |
| `1_process_creation/include_security_process_creation.xml` | New. Logs the same security tools starting or restarting | Elastic Defend reported only five `elastic-endpoint.exe` process records across both hosts all day, while Sysmon logged 105 starts on one. Without Event 1, Event 5 shows a stop but not the restart, its parent, or its command line |
| `11_file_create/include_elastic_sensor_file_tampering.xml`, `12_13_14_registry_event/include_elastic_service_tampering.xml`, `26_file_delete_detected/include_elastic_sensor_file_deletion.xml` | New | Tamper evidence, following the MDE sensor modules |

There is no Elastic exclusion for Event 25: Elastic Agent made 5 of the 7 Event 25 records, and an Event 25 exclusion by image would hide hollowing of that image.

The Agent collector runs from a versioned folder such as `C:\Program Files\Elastic\Agent\data\elastic-agent-9.4.4-baed89\components\`, so the modules match it with an anchored `begin with` and `end with` pair.

Modules that express a profile decision live in `modules/` here. The merger only discovers XML directly inside numbered directories, including `0_custom_configuration/`, so files in `modules/` never reach the release builds. CI's `validate --all-xml` still checks them.

`modules/research_base.xml` and `modules/complement_base.xml` are switchboards, with one filter per event. An `onmatch="exclude"` filter logs the event in full, apart from exclusions selected elsewhere. An empty `onmatch="include"` filter switches it off. A single include rule for a logged-in-full event would turn it into an allow-list, so the lists never select include modules for those events.

Sysmon applies only the first include filter and the first exclude filter it finds for an event ([olafhartong/sysmon-modular#226](https://github.com/olafhartong/sysmon-modular/issues/226)). The merger therefore combines each base filter with the modules' filters for the same event, so a generated profile has one include filter and one exclude filter per event.

Each base gives every event an explicit filter. Sysmon does not document what it does with an event that has no filter, and a default installation logs events 1, 2, 5, and 6. The complement base switches off every event it doesn't log in full, and `complement.txt` then selects include modules that log only what their rules match.

## Research profile

`research_base.xml` starts from the repository's former `sysmonconfig-research.xml`, removed in `0cefc18`. It makes these changes to the event filters:

- It narrows the `powershell.exe` RegistryEvent exclusion to `CreateKey`. The old exclusion hid every PowerShell registry change: on September 30, Elastic Defend recorded 641 and 552 PowerShell registry modifications on the two lab hosts, and Sysmon recorded none. On October 7, `CreateKey` made 516,117 of PowerShell's 516,717 registry events, mostly certificate-store key opens.
- `research.txt` adds `10_process_access/exclude_query_only_access.xml`, which excludes query-only process access: the masks 0x1000, 0x1400, 0x101000, and 0x101400, which can't read memory. On October 7 they made 530,793 of the 609,748 Event 10 records, 504,862 of them from `wmiprvse.exe`. Upstream's `exclude_lsass_noise.xml` also drops these masks, but it drops `taskmgr.exe` and other programs by name too.
- It drops the Splunk, Azure guest agent, Microsoft Monitoring Agent, and `C:\Tools` exclusions. None of those products ran in the lab, and on hosts without them a standard user can create `C:\WindowsAzure\GuestAgent*` or `C:\Tools\Sysinternals\` and hide a program there.
- FileBlockExecutable and FileBlockShredding have empty include filters, so nothing is blocked, as in the lab's derivative.
- It logs FileExecutableDetected (29) on Sysmon 15.

The root settings come from the repository template instead: `ArchiveDirectory` is `Sysmon` rather than `Research`, and `CheckRevocation` is `False`.

On September 30, Elastic Agent and Elastic Defend produced about 74% of the 5,038,347 indexed records, and the Elastic exclusions remove them. On October 7, the research profile logged 1,719,812 records in 6.6 hours. The two exclusions above remove 1,046,910 of them (61%), leaving about 673,000, or about 2.4 million a day on that host. Most of the rest is image loads (421,727, largely PowerShell, sshd, and csc driven by the Ansible harness). During evidence exports, the research host's mean CPU was more than twice the control's, and Sysmon events reached Elasticsearch up to 306 seconds late, though none were lost. Elastic Agent 8.x collects metrics in `components\agentbeat.exe`, which no exclusion covers yet. Run this profile on hosts with headroom and only as long as needed.

The research profile uses the upstream Event 3 module, which also excludes any program whose path ends in `winlogbeat.exe` or `packetbeat.exe`. Those rules come from upstream and are raised in the upstream issue draft.

Event 24 is logged, and Sysmon archives clipboard contents, which can include pasted passwords. Protect the archive folder, or switch Event 24 off when that matters. On the lab hosts archiving failed: all 10 Event 255 errors reported that `C:\Sysmon\` is not owned by SYSTEM. The Ansible role installs Sysmon into `C:\sysmon`, which is also the template's archive directory. Changing `ArchiveDirectory` may not be enough, because the lab profile set it to `Research` and the errors still named `C:\Sysmon\`. Move Sysmon's install folder (`sysmon_install_location`) instead.

## Complement profile

| Event | Collection | Lab evidence |
| --- | --- | --- |
| 1 | Security tools starting or restarting | Elastic Defend reported only five of its own process records all day; about 134 records a day on the lab host |
| 2 | Everything | No timestamp-change record in Elastic Defend on either host; 91 records all day |
| 5 | Security tools stopping, including Elastic Agent, its collector, and Elastic Defend | Sysmon recorded Elastic Defend's crash, and the Event 1 module records the restart |
| 6 | Everything | 3 records all day. Attackers load vulnerable signed drivers to stop security tools, and whether Elastic Defend records driver loads is unchecked |
| 8 | Everything | No thread-creation event in Elastic Defend; 8 records all day |
| 9 | Everything | No raw-device record in Elastic Defend; 178 records all day |
| 10 | Every LSASS open except the query-only masks (provisional) | No credential-access test was run, and Elastic Defend's credential hardening was off in both comparison policies. After the final lab profile: 13 records, all `wmiprvse.exe` with 0x1410 |
| 11 | Writes into the Elastic folders by other processes | Tamper evidence |
| 12–14 | Deletions and renames of keys of interest; value changes that switch off ETW autologgers, event log channels, or the Event Log service; changes to an event log's maximum size or retention; Elastic and Sysmon service tampering | Elastic Defend recorded no deletion all day, and value changes only for keys it watches: 1,840 on the Sysmon host against Sysmon's 43,658 |
| 15 | Selected file types | Elastic Defend saw the alternate data stream, but none of its 93,070 file events carried a hash |
| 17/18 | All named pipes, minus anonymous pipes, OpenSSH, Elastic, and the `\PSHost` pipe that PowerShell creates in itself | No pipe telemetry in Elastic Defend. On October 7, these exclusions left 437 of 3,192 pipe records in 6.6 hours |
| 19–21 | Everything | Elastic Defend recorded the registration API call but no deletion |
| 25 | Everything | Seven records all day, five from Elastic Agent |
| 26 | Selected locations and the Elastic folders, minus PowerShell's temporary files and Add-Type DLLs | The same hash gap. On October 7, every Event 26 record was an Add-Type DLL, whose hash Event 29 records when it's written |
| 29 | Selected tools and locations (provisional) | The same hash gap; not tested |
| 3 | Off. Optional module: inbound remote-access ports | Elastic Defend reported repeated inbound connections once: two `sshd.exe` records against Sysmon's 1,444 |
| 7, 22, 23, 24, 27, 28 | Off, with empty include filters | 22 overlapped with Elastic Defend; 7 is noisy and was not tested against malicious DLLs; 23, 27, and 28 archive or block files; 24 archives clipboard contents |

`complement.txt` lists the upstream modules this profile leaves out and why. In short, it skips:

- Exclusions that match a process name anywhere on disk, or a pipe name alone.
- Exclusions that match a path a standard user can create: programs in user profiles, unanchored `end with` paths, and `contains all C:\Program Files;...` rules, which also match a folder such as `C:\Program Files2\`. None of the affected applications ran in the lab, so these exclusions removed nothing from the measured data.
- Every Event 25 exclusion. Event 25 reports the image of the process that was tampered with, and any user can start a legitimate program and replace its image, so excluding an image hides that program's hollowing.
- Every Event 8 exclusion, including `exclude_generic_windows_processes.xml`, which also hides Ctrl-Inject. Event 8 produced 8 records all day.
- The Event 6 exclusions by signer. Intel's `iqvw64e.sys` is a well-known vulnerable driver, and many third-party drivers carry a Microsoft hardware-compatibility signature.
- `17_18_pipe_event/exclude_windows_generic.xml`, which drops `\srvsvc`, `\wkssvc`, `\lsass`, `\winreg`, and `\spoolss`.
- `10_process_access/include_lsass_access.xml`, which lists read masks and misses any mask it doesn't name, and `exclude_lsass_noise.xml`, which drops `taskmgr.exe` by name.

## Open items

- Exercise the complement's targeted rules, which the October 7 replay of September's tests didn't reach: delete a Run value, disable and re-enable a harmless event log channel, change a dummy service whose name starts with `Elastic`, restart the Sysmon service, write the streams `a.txt:b.bat` and `c.txt:d.vbs`, and dump LSASS once with Elastic Defend's credential hardening on.
- Measure both profiles' cost without evidence collection. The October 7 CPU and latency figures include the test harness's diagnostics and exports.
- Check the collector's `GrantedAccess` values. If they are essentially all `0x1000`, as its 24,377 LSASS accesses were, limit the Event 10 exclusion to that mask.
- Confirm the Elastic service and driver key names on a host. `include_elastic_service_tampering.xml` matches every service whose name starts with `Elastic`.
- Narrow the Elastic tamper modules for events 11, 12–14, and 26 to Elastic's own programs by full path. They trust any program under `C:\Program Files\Elastic\`, so an administrator could copy a tool there to avoid them. That needs the list of Elastic's executables from a host.
- Measure `include_deletions_of_interest.xml`. The lab data has deletion counts by process but not by key.
- Decide value changes for each persistence family in `include_deletions_of_interest.xml`: Run, Winlogon, IFEO, SilentProcessExit, AppInit, AppCertDlls, BootExecute, print monitors, time providers, NetSh, and logon scripts. If Elastic ships a rule on Elastic Defend's registry data for a family, leave its value changes to Elastic Defend; if not, add `SetValue` to that family's rule. A harmless test write to each key in the lab would show directly whether Elastic Defend records it.
- Measure the value changes on the Autologger and `WINEVT\Channels` keys during a cumulative update. The lab data has no breakdown by key.
- Decide whether to keep Event 29 for Add-Type compiles: `csc.exe` wrote 1,343 DLLs in 6.6 hours on the October 7 lab host, about 4,900 a day, and a malicious compile looks the same. `include_living_off_the_land.xml` also matches every executable that `msiexec.exe` writes.
- Events 1 and 5 also record Elastic Defend's short-lived helper processes (103 starts on the lab host) and any `elastic-agent.exe` command-line use.
- Check whether Elastic Defend records driver loads. If it reliably does, Event 6 can be switched off again.
- Test the remaining provisional rows: unsigned DLL loads (7) and executable drops (29).
- On Elastic Agent 8.x, measure `components\agentbeat.exe` and add it to the research exclusions if it is as noisy as the 9.x collector.
