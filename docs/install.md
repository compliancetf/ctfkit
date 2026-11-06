# Install

ctfkit by compliance.tf ships as a Homebrew formula, release archives and Linux packages. Releases are published on
[GitHub Releases](https://github.com/compliancetf/ctfkit/releases) and download without a
token. User documentation lives at <https://compliance.tf/docs/ctfkit/>.

## Homebrew

On macOS and Linux (arm64 or x86_64):

```bash
brew install compliancetf/tap/ctfkit
ctfkit version
```

The formula lives in [compliancetf/homebrew-tap](https://github.com/compliancetf/homebrew-tap)
and installs the newest release; `brew upgrade ctfkit` moves to the next one. The tap updates
within a day of a release. Before it pins an archive's SHA-256, it checks the archive's build
provenance attestation (below), so the formula only installs archives the ctfkit release
workflow built. For a reproducible CI job or image, install a pinned release archive instead.

## Release archives

Every tagged release has pre-built archives for Linux (x86_64, arm64, armv7), macOS (x86_64,
arm64) and Windows (x86_64, and arm64 since v0.4.0), plus `checksums.txt`. This downloads the newest release and checks
the archive before you unpack it:

```bash
gh release download --repo compliancetf/ctfkit \
    --pattern 'ctfkit_*_Linux_x86_64.tar.gz' --pattern checksums.txt &&
  sha256sum --ignore-missing -c checksums.txt &&
  tar -xzf ctfkit_*_Linux_x86_64.tar.gz ctfkit &&
  sudo install -m 0755 ctfkit /usr/local/bin/ctfkit &&
  ctfkit version
```

`gh release download` without a tag takes the newest release. To pin one, put its tag after
`download`, such as `gh release download v1.2.3`; pin in CI and in images you build, so a new
release changes nothing until you move the pin. Other platforms follow the same pattern:
`ctfkit_<version>_<Os>_<arch>.tar.gz`, such as `ctfkit_*_Darwin_arm64.tar.gz`, and a `.zip` for
Windows ([Windows](#windows)). v0.3.0 is the first stable release published in this repository.

`checksums.txt` comes from the same release as the archive. It shows that the download is intact
and says nothing about who built it. To rule out a replaced release, pin the digest you reviewed.

The release workflow also creates a GitHub build provenance attestation covering every file in
`checksums.txt`. It shows which workflow run built the file:

```bash
tag="$(gh release view --repo compliancetf/ctfkit --json tagName --jq .tagName)"
gh attestation verify ctfkit_*_Linux_x86_64.tar.gz --repo compliancetf/ctfkit \
  --signer-workflow compliancetf/ctfkit/.github/workflows/release.yml \
  --source-ref "refs/tags/$tag"
```

### Windows

In PowerShell, this downloads the newest x86_64 release, checks it against `checksums.txt` and
unpacks `ctfkit.exe` into `$env:LOCALAPPDATA\ctfkit`. On Windows on Arm, use `arm64` in place of
`x86_64`.

```powershell
$ErrorActionPreference = "Stop"
$base = "https://github.com/compliancetf/ctfkit/releases/latest/download"
Invoke-WebRequest "$base/checksums.txt" -OutFile checksums.txt -UseBasicParsing
$line = Select-String -Path checksums.txt -Pattern "ctfkit_.*_Windows_x86_64\.zip$"
$hash, $zip = $line.Line.Trim() -split "\s+"
Invoke-WebRequest "$base/$zip" -OutFile $zip -UseBasicParsing
if ((Get-FileHash $zip -Algorithm SHA256).Hash -ne $hash) { throw "checksum mismatch: $zip" }
Expand-Archive $zip -DestinationPath "$env:LOCALAPPDATA\ctfkit" -Force
& "$env:LOCALAPPDATA\ctfkit\ctfkit.exe" version
```

Add `$env:LOCALAPPDATA\ctfkit` to your `PATH` to run `ctfkit` from any directory. To pin a
release, replace `latest/download` with `download/v1.2.3`. With `gh`, use
`gh release download --repo compliancetf/ctfkit --pattern 'ctfkit_*_Windows_x86_64.zip' --pattern checksums.txt`.
The release binaries are not code-signed, so SmartScreen may warn on the first run.

### Without gh

The newest release is always at <https://github.com/compliancetf/ctfkit/releases/latest>, and
`https://github.com/compliancetf/ctfkit/releases/latest/download/checksums.txt` lists its archive
names. Download with any HTTP client from the same directory, for example
`https://github.com/compliancetf/ctfkit/releases/download/v<version>/ctfkit_<version>_Linux_x86_64.tar.gz`. Check the file against `checksums.txt` as above.

## deb, rpm and apk packages

The same release has `.deb`, `.rpm` and `.apk` packages. Download one with `gh release download`
as above, check it against `checksums.txt`, and install it with `dpkg -i`, `rpm -i` or
`apk add --allow-untrusted`. The packages are not signed, which is why `apk` needs
`--allow-untrusted`; the checksum is the only integrity check.

## Pre-commit hook

<!-- x-release-please-start-version -->
```yaml
repos:
  - repo: https://github.com/compliancetf/ctfkit
    rev: v0.4.2
    hooks:
      - id: ctfkit
```
<!-- x-release-please-end -->

`pre-commit autoupdate` moves `rev` to the newest release.

The repository defines two hook ids. Pick one per repository:

| Hook id | Runs | Pick it for |
|---|---|---|
| `ctfkit` | `ctfkit scan --stage pre_plan <staged files>`, file-list mode | a repository of deployable roots: only the changed files are read, and every finding in them is reported |
| `ctfkit-scan-dir` | `ctfkit scan --stage pre_plan .` once, from the repository root, whenever a Terraform or OpenTofu file changes | a module repository: the directory scan tells reusable modules from deployable roots, so `ctf.origin.provider_unpinned` stays quiet on the minimum-only constraints a module is meant to declare ([Provider constraints in reusable modules](analyzers.md#provider-constraints-in-reusable-modules)) |

Both run on `.tf`, `.tofu`, `.tf.json` and `.tofu.json` files outside `.terraform/`.
`ctfkit-scan-dir` is available since v0.3.0. In a module
repository, the `.pre-commit-config.yaml` entry is:

<!-- x-release-please-start-version -->
```yaml
repos:
  - repo: https://github.com/compliancetf/ctfkit
    rev: v0.4.2
    hooks:
      - id: ctfkit-scan-dir
```
<!-- x-release-please-end -->

`ctfkit-scan-dir` reads the whole repository on every run, so it is slower on a large tree and
also reports findings in files the commit did not touch.

The hook builds from source, so Go must be installed. To use an installed binary instead, with
the same behaviour as the published `ctfkit` hook:

```yaml
repos:
  - repo: local
    hooks:
      - id: ctfkit
        name: ctfkit
        entry: ctfkit scan --stage pre_plan
        language: system
        files: \.(tf|tofu)(\.json)?$
        exclude: \.terraform/
        pass_filenames: true
```

For the behaviour of `ctfkit-scan-dir`, set `entry: ctfkit scan --stage pre_plan .`,
`pass_filenames: false` and `require_serial: true`.

## Container image

Every release publishes a multi-arch image (linux/amd64, linux/arm64) with the binary on a
distroless, non-root base. `latest` is the newest release:

```bash
docker run --rm -v "$PWD:/work" -w /work ghcr.io/compliancetf/ctfkit scan --stage pre_plan .
```

To pin a release, use its version as the tag, such as `ghcr.io/compliancetf/ctfkit:1.2.3`.

## Check the install

`ctfkit version` prints the version, commit, build date, Go version and platform
([commands.md](commands.md#ctfkit-version)). `ctfkit --help` lists the commands.
