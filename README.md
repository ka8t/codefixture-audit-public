# codefixture-audit

Security scanner for source code by [CodeFixture](https://codefixture.com). It analyzes Python, Java, JavaScript/TypeScript, PHP, C#, HTML, YAML and Dockerfile sources, including data-flow (taint) analysis, and writes an HTML report.

This repository holds the complete engine and a sample of its detection rules. The analysis runs on your machine: your code never leaves it.

## Known limits

Read this before you start: these are the cases where the engine may not behave as you expect.

| Limit | What it means for you |
|---|---|
| **Tested on macOS and Linux** | Linux was checked on Ubuntu 24.04. Windows has not been tested yet: the Windows commands are given but have never been run; please report any problem. |
| **The first analysis takes two runs** | The first command asks 2 or 3 questions (press Enter to keep the defaults), writes `audit.config.json` in your project, then stops and asks you to run the same command again. The second run produces the report. |
| **The demo rules give a thin report** | This repository ships 38 demonstration rules, a small part of the catalog. Without the full rule pack, most findings may come from a few rules (for example JavaScript written in HTML attributes). |
| **The demo pack knows few published vulnerabilities** | Your dependencies are compared with the 21 well-known vulnerabilities this repository's pack carries (Log4Shell, Spring4Shell, lodash, lxml…). A dependency not reported may still be affected by another one. The full pack carries every published vulnerability of the five ecosystems. |
| **First installation takes time** | Installing Rust and the first build take about 10 to 15 minutes. Later builds and analyses are much faster. |

Details and workarounds: [Known limits](INSTALLATION.md#known-limits) in the guide.

## Analyse a folder

Once the engine is built (see below), run from the `codefixture-audit-public` folder, replacing the path with the folder of your code:

macOS:

```bash
./target/release/codefixture-audit scan /path/to/your/project --lang en
```

Windows (PowerShell):

```powershell
.\target\release\codefixture-audit.exe scan C:\path\to\your\project --lang en
```

- `--lang` sets the report language: `en`, `fr`, `es` or `de`.
- When your project declares dependencies (`requirements.txt`, `package.json`, `pom.xml`, `composer.json`, `.csproj`…), their pinned versions are compared with the published vulnerabilities the rule pack carries, offline. A vulnerability that CISA lists as exploited in real attacks (KEV) makes the finding critical, and each CVE shows its EPSS score, the probability that it gets exploited in the next 30 days.
- `--sbom` also writes a CycloneDX SBOM (software bill of materials) of the dependencies your project declares: see [SBOM export](INSTALLATION.md#sbom-export).
- The first run on a project asks what to analyse and writes `audit.config.json`; run the same command again for the analysis.
- The report is written into your project, under `audit-reports/`: the terminal prints its path on the `Report generated` line. Open it in a browser.

## First installation

From nothing installed to the first analysis, in a terminal (macOS):

```bash
xcode-select --install
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# close and reopen the Terminal, then:
cd ~
git clone https://github.com/ka8t/codefixture-audit-public.git
cd codefixture-audit-public
cargo build --release
./target/release/codefixture-audit scan /path/to/your/project --lang en
```

Windows (PowerShell):

```powershell
winget install Git.Git
winget install Rustlang.Rustup
winget install Microsoft.VisualStudio.2022.BuildTools --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
# close and reopen PowerShell, then:
cd ~
git clone https://github.com/ka8t/codefixture-audit-public.git
cd codefixture-audit-public
cargo build --release
.\target\release\codefixture-audit.exe scan C:\path\to\your\project --lang en
```

[`INSTALLATION.md`](INSTALLATION.md) takes you step by step from download to a full analysis of your own code: installing the tools, building the engine, describing your project, running the analysis, reading the report (your code, the proposed fix, the data-flow path) and analysing again after a fix.

The sample rules come compiled into one file, `rules/rules.cfpack`: the engine you build uses it at once, and the two can be moved anywhere together. Each scan keeps only the rules of the scanned project's languages: see [step 7](INSTALLATION.md#step-7-describe-your-project-first-run).

## Already installed?

From your `codefixture-audit-public` folder:

```bash
git pull
cargo build --release
```

With the full rule catalog, copy `rules.cfpack` next to the engine again afterwards: see [step 11](INSTALLATION.md#step-11-update-the-engine).

## Full rule catalog

The sample covers a small part of what the engine detects. The full catalog has more than 700 rules and is available from [CodeFixture](https://codefixture.com), with its updates, as a rule pack that replaces the sample one, with every published vulnerability of the five ecosystems: see [step 6](INSTALLATION.md#step-6-add-the-full-catalog-optional).

## Vulnerability data

The published vulnerabilities and the exploitation data in the rule packs come from these databases, each used under its license:

| Database | License |
|---|---|
| [GitHub Advisory Database](https://github.com/github/advisory-database), through [OSV](https://osv.dev) | CC-BY 4.0 |
| [PyPI Advisory Database](https://github.com/pypa/advisory-database), through OSV | CC-BY 4.0 |
| [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages), through OSV | Apache 2.0 |
| [Drupal security advisories](https://www.drupal.org/security), through OSV | MIT |
| [OSS-Fuzz](https://github.com/google/oss-fuzz-vulns), through OSV | CC-BY 4.0 |
| [Erlang Ecosystem Foundation CNA](https://cna.erlef.org), through OSV | CC-BY 4.0 |
| [FriendsOfPHP security advisories](https://github.com/FriendsOfPHP/security-advisories) | Unlicense |
| [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CC0 1.0 |
| [FIRST EPSS](https://www.first.org/epss) | [EPSS usage agreement](https://www.first.org/epss/#Usage-Agreement), credit requested |

The records are reduced to the package names and affected versions the engine compares. Each report lists the databases its rule pack used, in its scope table.

## License

Proprietary evaluation license — see [`LICENSE`](LICENSE). You may build and test the engine to evaluate it; any other use, including within a company, requires an agreement with [CodeFixture](https://codefixture.com).
