# sysmon-modular-elastic | A Sysmon configuration repository for everybody to customise

This project is forked from Olaf Hartong's original [sysmon-modular](https://github.com/olafhartong/sysmon-modular). 

The goal of this repository is to provide usable sysmon configurations to use in combination with Elastic Defend.

## Download

Both profiles need Sysmon 15.21 or later. They always come from the newest [release](https://github.com/DetectionDude/sysmon-modular-elastic/releases/latest), which CI builds on every push to `elastic`.

| Profile | Download | Use it to |
| --- | --- | --- |
| Complement | [`sysmonconfig-elastic-complement.xml`](https://github.com/DetectionDude/sysmon-modular-elastic/releases/latest/download/sysmonconfig-elastic-complement.xml) | Run next to Elastic Defend. It logs only what Defend doesn't record, plus evidence of Defend being stopped or tampered with. |
| Research | [`sysmonconfig-elastic-research.xml`](https://github.com/DetectionDude/sysmon-modular-elastic/releases/latest/download/sysmonconfig-elastic-research.xml) | Log every event except Elastic Agent and Elastic Defend noise. For short, controlled research sessions: an estimated 2.4 million records a day on a busy lab host. |

Verify a download against [`SHA256SUMS`](https://github.com/DetectionDude/sysmon-modular-elastic/releases/latest/download/SHA256SUMS), then load it:

```powershell
Sysmon64.exe -c .\sysmonconfig-elastic-complement.xml
```

The [profile README](0_custom_configuration/elastic/README.md) explains every choice and how to generate the files yourself.
