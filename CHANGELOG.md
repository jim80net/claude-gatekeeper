# Changelog

## [1.1.0](https://github.com/jim80net/claude-gatekeeper/compare/v1.0.0...v1.1.0) (2026-03-08)


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
