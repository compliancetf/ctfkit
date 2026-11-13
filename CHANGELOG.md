# Changelog

## [0.10.0](https://github.com/compliancetf/ctfkit/compare/v0.9.0...v0.10.0) (2026-11-13)


### Features

* **action:** name the action ctfkit by compliance.tf for the Marketplace listing ([#46](https://github.com/compliancetf/ctfkit/issues/46)) ([a0e3ad5](https://github.com/compliancetf/ctfkit/commit/a0e3ad5eda1436ab9e3d6b9a43374689b3e1d768))

## [0.9.0](https://github.com/compliancetf/ctfkit/compare/v0.8.0...v0.9.0) (2026-11-12)


### Features

* **sarif:** rule name, help, docs link, tags and severity for code scanning ([#44](https://github.com/compliancetf/ctfkit/issues/44)) ([55503bb](https://github.com/compliancetf/ctfkit/commit/55503bbe98381b4752e6b3ddfb262eaf7e82e969))

## [0.8.0](https://github.com/compliancetf/ctfkit/compare/v0.7.1...v0.8.0) (2026-11-12)


### Features

* **report:** write an evidence pack with a PDF to --out-dir ([#41](https://github.com/compliancetf/ctfkit/issues/41)) ([ee23fc0](https://github.com/compliancetf/ctfkit/commit/ee23fc085c93c3f93b91e2fed1d2026035b4f624))

## [0.7.1](https://github.com/compliancetf/ctfkit/compare/v0.7.0...v0.7.1) (2026-11-11)


### Bug fixes

* **analyzer:** close module source and program-execution coverage gaps ([#36](https://github.com/compliancetf/ctfkit/issues/36)) ([85281dc](https://github.com/compliancetf/ctfkit/commit/85281dc13a9da0a9a803c1b8d9d9dd403613c474))
* **cli:** confine output paths and harden runtask, evidence spool and markdown values ([#38](https://github.com/compliancetf/ctfkit/issues/38)) ([751bda1](https://github.com/compliancetf/ctfkit/commit/751bda1048e3611fd069c898720390d35339f3b1))
* **gate:** bind the terraform digest and refuse forked AWS providers under governed profiles ([#37](https://github.com/compliancetf/ctfkit/issues/37)) ([c8ade14](https://github.com/compliancetf/ctfkit/commit/c8ade144e2a01624b495005a4431e693ece9c9e2))

## [0.7.0](https://github.com/compliancetf/ctfkit/compare/v0.6.0...v0.7.0) (2026-11-10)


### Features

* **action:** add catalog: pull to download the full control catalog ([#31](https://github.com/compliancetf/ctfkit/issues/31)) ([57e6625](https://github.com/compliancetf/ctfkit/commit/57e6625ae194b935855af8f58447657eac4f87c4))

## [0.6.0](https://github.com/compliancetf/ctfkit/compare/v0.5.0...v0.6.0) (2026-11-09)


### Features

* **catalog:** add ctfkit catalog pull ([#29](https://github.com/compliancetf/ctfkit/issues/29)) ([43d6ce4](https://github.com/compliancetf/ctfkit/commit/43d6ce47a2c6e0bcda6c35fc7c552afd61f77f13))

## [0.5.0](https://github.com/compliancetf/ctfkit/compare/v0.4.1...v0.5.0) (2026-11-09)


### ⚠ BREAKING CHANGES

* **catalog:** with the embedded catalog, findings carry control ids and frameworks for CIS v6.0 controls only. A control-keyed exception for a control outside CIS v6.0 no longer matches; use a rule entry or load the full catalog. ctf.policy.disabled_control_unknown is reported at error level instead of warning.

### Features

* **catalog:** embed the CIS AWS Benchmark v6.0 controls only ([#28](https://github.com/compliancetf/ctfkit/issues/28)) ([4daade7](https://github.com/compliancetf/ctfkit/commit/4daade780d8c397800f01c27e7e52d036ebc199a))


### Bug fixes

* **catalog:** retire CIS AWS Benchmark v1.2.0, v1.3.0 and v1.4.0 ([#24](https://github.com/compliancetf/ctfkit/issues/24)) ([3306cd8](https://github.com/compliancetf/ctfkit/commit/3306cd868d9454982ccb5ff5c3e58a89c13090da))

## [0.4.1](https://github.com/compliancetf/ctfkit/compare/v0.4.0...v0.4.1) (2026-11-05)


### Bug fixes

* drop the preview label; every shipped command is available ([#22](https://github.com/compliancetf/ctfkit/issues/22)) ([6003e0f](https://github.com/compliancetf/ctfkit/commit/6003e0fd31793210641e5b1250302ecc4db10731))

## [0.4.0](https://github.com/compliancetf/ctfkit/compare/v0.3.0...v0.4.0) (2026-11-04)


### Features

* Homebrew formula in compliancetf/homebrew-tap and a Windows arm64 build ([#19](https://github.com/compliancetf/ctfkit/issues/19)) ([f49cc3b](https://github.com/compliancetf/ctfkit/commit/f49cc3ba97b13fe1afe8a2a142ad1412cd4f76ac))

## [0.3.0](https://github.com/compliancetf/ctfkit/compare/v0.3.0-preview.5...v0.3.0) (2026-11-04)


### Features

* plain semver releases; the action installs the latest ctfkit by default ([#17](https://github.com/compliancetf/ctfkit/issues/17)) ([e1127ab](https://github.com/compliancetf/ctfkit/commit/e1127ab032532d8f9337409639a26d793128affe))


### Dependencies

* bump golang.org/x/sys from 0.48.0 to 0.49.0 in the go-patch-minor group across 1 directory ([#14](https://github.com/compliancetf/ctfkit/issues/14)) ([58c9037](https://github.com/compliancetf/ctfkit/commit/58c90373786d396a4d8849a26d14d9d46d96905f))

## [0.3.0-preview.5](https://github.com/compliancetf/ctfkit/compare/v0.3.0-preview.4...v0.3.0-preview.5) (2026-11-04)


### Bug fixes

* build with Go 1.27 ([c770bea](https://github.com/compliancetf/ctfkit/commit/c770bea0a61c8b654cd78341289dbb8ee9ee3aab))


### Dependencies

* bump Go modules that build on Go 1.25 ([#9](https://github.com/compliancetf/ctfkit/issues/9)) ([f25e49e](https://github.com/compliancetf/ctfkit/commit/f25e49e3cce29f4c24908b79f0b3ef6d7ba30c09))

## [0.3.0-preview.4](https://github.com/compliancetf/ctfkit/compare/v0.3.0-preview.3...v0.3.0-preview.4) (2026-11-03)


### Dependencies

* bump golang.org/x/text to v0.39.0 ([#3](https://github.com/compliancetf/ctfkit/issues/3)) ([0544f8b](https://github.com/compliancetf/ctfkit/commit/0544f8b06e4d61db1ab6c491c6d329ae787466de))

## [0.3.0-preview.3](https://github.com/compliancetf/ctfkit/compare/v0.3.0-preview.2...v0.3.0-preview.3) (2026-11-03)


### Features

* initial public release of ctfkit by compliance.tf ([6743a77](https://github.com/compliancetf/ctfkit/commit/6743a77c0681d8fe13331c7ec9825e2ed9c3c2ee))

## Changelog

All notable changes to ctfkit by compliance.tf are listed here. The release workflow
writes each entry from the conventional commits merged since the previous release.
