# Changelog

## [1.7.1](https://github.com/jim80net/gatekeeper-claude/compare/v1.7.0...v1.7.1) (2026-08-22)


### Bug Fixes

* honor on_error=deny when Core 6086c496 rejects invalid rules at LoadFile ([#77](https://github.com/jim80net/gatekeeper-claude/issues/77)) ([3f8a386](https://github.com/jim80net/gatekeeper-claude/commit/3f8a386dedff470c9d25b62c324ea4c083263897))

## [1.7.0](https://github.com/jim80net/gatekeeper-claude/compare/v1.6.0...v1.7.0) (2026-08-04)


### Features

* add authorization domains D1 shadow contracts ([#66](https://github.com/jim80net/gatekeeper-claude/issues/66)) ([a199fb9](https://github.com/jim80net/gatekeeper-claude/commit/a199fb96efbaedfce7ccc0336732e1f6138e3d23))
* add scheduled Doctor version invariant ([#72](https://github.com/jim80net/gatekeeper-claude/issues/72)) ([668f42b](https://github.com/jim80net/gatekeeper-claude/commit/668f42b0d08c1c2029c352c6656aff477d89b680))


### Bug Fixes

* parse single-dash Doctor harness flags ([#71](https://github.com/jim80net/gatekeeper-claude/issues/71)) ([2c36e70](https://github.com/jim80net/gatekeeper-claude/commit/2c36e7008102b88b251bb31fd9a7892b7f70361f))
* resolve bare Doctor commands through PATH ([#65](https://github.com/jim80net/gatekeeper-claude/issues/65)) ([6c0a9f5](https://github.com/jim80net/gatekeeper-claude/commit/6c0a9f5b05f3cd98579144cb8ca50655583e0aea))

## [1.6.0](https://github.com/jim80net/gatekeeper-claude/compare/v1.5.1...v1.6.0) (2026-07-25)


### Features

* add one-command release verification ([#63](https://github.com/jim80net/gatekeeper-claude/issues/63)) ([1082ed2](https://github.com/jim80net/gatekeeper-claude/commit/1082ed23490f1fcd843a3a7011a1349205e078c6))

## [1.5.1](https://github.com/jim80net/gatekeeper-claude/compare/v1.5.0...v1.5.1) (2026-07-19)


### Bug Fixes

* preserve fail-closed posture when policy is unreadable ([#58](https://github.com/jim80net/gatekeeper-claude/issues/58)) ([54ba327](https://github.com/jim80net/gatekeeper-claude/commit/54ba327cdc8eef208eb39b8c220ce67d3efa2efe))

## [1.5.0](https://github.com/jim80net/gatekeeper-claude/compare/v1.4.1...v1.5.0) (2026-07-18)


### Features

* add declarative policy test harness ([#56](https://github.com/jim80net/gatekeeper-claude/issues/56)) ([ff03377](https://github.com/jim80net/gatekeeper-claude/commit/ff033770a68f273f6f0fd442fe4ae2b07e408a91))


### Bug Fixes

* migrate goreleaser archives to formats lists and check config in CI ([#49](https://github.com/jim80net/gatekeeper-claude/issues/49), [#54](https://github.com/jim80net/gatekeeper-claude/issues/54)) ([0f376d3](https://github.com/jim80net/gatekeeper-claude/commit/0f376d383b37c22b1ffd8940b9040212badab05f))

## [1.4.1](https://github.com/jim80net/gatekeeper-claude/compare/v1.4.0...v1.4.1) (2026-07-14)


### Bug Fixes

* pin goreleaser project_name to claude-gatekeeper ([#48](https://github.com/jim80net/gatekeeper-claude/issues/48)) ([3834002](https://github.com/jim80net/gatekeeper-claude/commit/383400247844ad77de04578199dcec20f5524e9b))
* plugin wrapper fails closed when the gatekeeper binary cannot be obtained ([#25](https://github.com/jim80net/gatekeeper-claude/issues/25), [#51](https://github.com/jim80net/gatekeeper-claude/issues/51)) ([8a036d9](https://github.com/jim80net/gatekeeper-claude/commit/8a036d92b87de8afe51c2c4186b7522aa4298dea))
* verify grok non-shell tool inputs against shipped 0.2.101 contract ([#26](https://github.com/jim80net/gatekeeper-claude/issues/26), [#52](https://github.com/jim80net/gatekeeper-claude/issues/52)) ([54e07e6](https://github.com/jim80net/gatekeeper-claude/commit/54e07e62e02f4c65441adcdc3c77a3d8f5d5b249))

## [1.4.0](https://github.com/jim80net/gatekeeper-claude/compare/v1.3.1...v1.4.0) (2026-07-14)


### Features

* add fleet hook inventory doctor command ([#38](https://github.com/jim80net/gatekeeper-claude/issues/38)) ([c7e2a98](https://github.com/jim80net/gatekeeper-claude/commit/c7e2a9889c74395a7d9ced8568085c46ecf9f7af))


### Bug Fixes

* **engine:** domain-scope merge authority via GATEKEEPER_INPUT ([#34](https://github.com/jim80net/gatekeeper-claude/issues/34)) ([681e8ac](https://github.com/jim80net/gatekeeper-claude/commit/681e8ac9ee3b2ea1892684f2c5a8afec177afa6a))
* fail closed on untrusted Codex hooks ([#28](https://github.com/jim80net/gatekeeper-claude/issues/28), [#46](https://github.com/jim80net/gatekeeper-claude/issues/46)) ([c7e2a98](https://github.com/jim80net/gatekeeper-claude/commit/c7e2a9889c74395a7d9ced8568085c46ecf9f7af))
* force-push deny rule matches the force flag anywhere in the command ([#33](https://github.com/jim80net/gatekeeper-claude/issues/33), [#45](https://github.com/jim80net/gatekeeper-claude/issues/45)) ([c7e2a98](https://github.com/jim80net/gatekeeper-claude/commit/c7e2a9889c74395a7d9ced8568085c46ecf9f7af))

## [1.3.1](https://github.com/jim80net/claude-gatekeeper/compare/v1.3.0...v1.3.1) (2026-07-08)


### Bug Fixes

* **codex:** never emit unsupported permissionDecision:allow ([fa2c910](https://github.com/jim80net/claude-gatekeeper/commit/fa2c91002805eaaf054e7552f7615cc628101758))

## [1.3.0](https://github.com/jim80net/claude-gatekeeper/compare/v1.2.0...v1.3.0) (2026-07-03)


### Features

* harness-agnostic core + codex/grok adapters, configurable on_error ([#21](https://github.com/jim80net/claude-gatekeeper/issues/21)) ([ee44df3](https://github.com/jim80net/claude-gatekeeper/commit/ee44df395435f4dfa5e31eda818f2ac26e178311))


### Bug Fixes

* **grok:** correct hook wire schema + install format; Q1 live-verified PASS ([#23](https://github.com/jim80net/claude-gatekeeper/issues/23)) ([d827da9](https://github.com/jim80net/claude-gatekeeper/commit/d827da9a4f1a7781e7ebbc2434f24c3b380c8a15))

## [1.2.0](https://github.com/jim80net/claude-gatekeeper/compare/v1.1.1...v1.2.0) (2026-03-17)


### Features

* add learn-approvals skill ([#15](https://github.com/jim80net/claude-gatekeeper/issues/15)) ([ef7175e](https://github.com/jim80net/claude-gatekeeper/commit/ef7175ed525f0878f3c8f012660bda75e80bbaea))


### Bug Fixes

* chain goreleaser into release-please workflow ([#16](https://github.com/jim80net/claude-gatekeeper/issues/16)) ([e318a86](https://github.com/jim80net/claude-gatekeeper/commit/e318a86e9cd64bd672a779285d8f9ed2fc4ec26c))
* chain goreleaser into release-please workflow ([#16](https://github.com/jim80net/claude-gatekeeper/issues/16)) ([20a4a10](https://github.com/jim80net/claude-gatekeeper/commit/20a4a10ff7b003dc73e902ee6e25ae93f4757026))

## [1.1.1](https://github.com/jim80net/claude-gatekeeper/compare/v1.1.1...v1.1.1) (2026-03-17)


### Features

* add learn-approvals skill ([#15](https://github.com/jim80net/claude-gatekeeper/issues/15)) ([ef7175e](https://github.com/jim80net/claude-gatekeeper/commit/ef7175ed525f0878f3c8f012660bda75e80bbaea))


### Bug Fixes

* chain goreleaser into release-please workflow ([#16](https://github.com/jim80net/claude-gatekeeper/issues/16)) ([e318a86](https://github.com/jim80net/claude-gatekeeper/commit/e318a86e9cd64bd672a779285d8f9ed2fc4ec26c))
* chain goreleaser into release-please workflow ([#16](https://github.com/jim80net/claude-gatekeeper/issues/16)) ([20a4a10](https://github.com/jim80net/claude-gatekeeper/commit/20a4a10ff7b003dc73e902ee6e25ae93f4757026))

## [1.1.1](https://github.com/jim80net/claude-gatekeeper/compare/v1.0.0...v1.1.1) (2026-03-08)


### Features

* add /claude-gatekeeper:help skill showing rules and config ([85ed22f](https://github.com/jim80net/claude-gatekeeper/commit/85ed22f8ac9be7edc85f9abcaae392e8f1d773b9))
* allow non-recursive rm on files in build output directories ([990ae63](https://github.com/jim80net/claude-gatekeeper/commit/990ae632e071a984df1ff1dbcd7187e2701109d6))
* allow recursive delete on common build output directories ([9c41502](https://github.com/jim80net/claude-gatekeeper/commit/9c41502a5484e934441c79c216859df0c12f414b))
* allow recursive delete on common build output directories ([ca9fe6b](https://github.com/jim80net/claude-gatekeeper/commit/ca9fe6b9b658b3c1b4b1ea5d9e502cef961883e8))


### Bug Fixes

* enable model invocation for help skill ([6a579cc](https://github.com/jim80net/claude-gatekeeper/commit/6a579ccf437859398e22df34e99d350a5d52cf08))
* prepend cd prefix to preconditions for correct directory context ([7c6da5e](https://github.com/jim80net/claude-gatekeeper/commit/7c6da5e97e09f73cfdd60d9f9f47deab536744be))
* prevent multi-target bypass in rm -rf exemption rule ([b217f68](https://github.com/jim80net/claude-gatekeeper/commit/b217f68bfa203f68aff30d93d26299318f36a0cc))
* strip heredoc bodies before matching deny rules ([08ddccc](https://github.com/jim80net/claude-gatekeeper/commit/08ddccc0c9986f45962aa1fddc686be1f99be72e))
* strip heredoc bodies before matching deny rules ([c4d3542](https://github.com/jim80net/claude-gatekeeper/commit/c4d35423d4190aac2dae608bb12f7e830048a9dc))
