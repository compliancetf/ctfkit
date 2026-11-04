# Install

ctfkit by compliance.tf ships as release archives and Linux packages. Releases are published on
[GitHub Releases](https://github.com/compliancetf/ctfkit/releases) and download without a
token. User documentation lives at <https://compliance.tf/docs/ctfkit/>.

## Release archives

Every tagged release has pre-built archives for Linux (x86_64, arm64, armv7), macOS (x86_64,
arm64) and Windows (x86_64), plus `checksums.txt`. Check the archive before you unpack it:

```bash
V=0.3.0-preview.5 # x-release-please-version
gh release download "v$V" --repo compliancetf/ctfkit \
  --pattern "ctfkit_${V}_Linux_x86_64.tar.gz" --pattern checksums.txt
awk -v f="ctfkit_${V}_Linux_x86_64.tar.gz" '$2 == f' checksums.txt | sha256sum -c -
tar -xzf "ctfkit_${V}_Linux_x86_64.tar.gz" ctfkit
sudo install -m 0755 ctfkit /usr/local/bin/ctfkit
ctfkit version
```

Other platforms follow the same pattern: `ctfkit_<version>_<Os>_<arch>.tar.gz`, such as
`ctfkit_${V}_Darwin_arm64.tar.gz`, and a `.zip` for Windows. Releases before v0.3.0-preview.3
were not published in this repository.

`checksums.txt` comes from the same release as the archive. It shows that the download is intact
and says nothing about who built it. To rule out a replaced release, pin the digest you reviewed.

The release workflow also creates a GitHub build provenance attestation covering every file in
`checksums.txt`. It shows which workflow run built the file:

```bash
gh attestation verify "ctfkit_${V}_Linux_x86_64.tar.gz" --repo compliancetf/ctfkit \
  --signer-workflow compliancetf/ctfkit/.github/workflows/release.yml \
  --source-ref "refs/tags/v$V"
```

### Without gh

Download from the release page with any HTTP client, for example
`https://github.com/compliancetf/ctfkit/releases/download/v<version>/ctfkit_<version>_Linux_x86_64.tar.gz`,
and `checksums.txt` from the same directory. Check the file against `checksums.txt` as above.

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
    rev: v0.3.0-preview.5
    hooks:
      - id: ctfkit
```
<!-- x-release-please-end -->

The repository defines two hook ids. Pick one per repository:

| Hook id | Runs | Pick it for |
|---|---|---|
| `ctfkit` | `ctfkit scan --stage pre_plan <staged files>`, file-list mode | a repository of deployable roots: only the changed files are read, and every finding in them is reported |
| `ctfkit-scan-dir` | `ctfkit scan --stage pre_plan .` once, from the repository root, whenever a Terraform or OpenTofu file changes | a module repository: the directory scan tells reusable modules from deployable roots, so `ctf.origin.provider_unpinned` stays quiet on the minimum-only constraints a module is meant to declare ([Provider constraints in reusable modules](analyzers.md#provider-constraints-in-reusable-modules)) |

Both run on `.tf`, `.tofu`, `.tf.json` and `.tofu.json` files outside `.terraform/`.
`ctfkit-scan-dir` is available since v0.3.0-preview.1. In a module
repository, the `.pre-commit-config.yaml` entry is:

<!-- x-release-please-start-version -->
```yaml
repos:
  - repo: https://github.com/compliancetf/ctfkit
    rev: v0.3.0-preview.5
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

Every release from v0.3.0-preview.3 on publishes a multi-arch image (linux/amd64, linux/arm64)
with the binary on a distroless, non-root base:

```bash
docker run --rm -v "$PWD:/work" -w /work ghcr.io/compliancetf/ctfkit:<version> scan --stage pre_plan .
```

Preview releases never move the `latest` tag. A Homebrew cask is planned.

## Check the install

`ctfkit version` prints the version, commit, build date, Go version and platform
([commands.md](commands.md#ctfkit-version)). `ctfkit --help` lists the commands.
