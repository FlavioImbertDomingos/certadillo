# Contributing

1. Fork, branch from `main`, keep pull requests to one change.
2. `make dev && make lint && make test` must pass. Protocol changes also need `make interop` (certbot against a live server).
3. New behaviour needs a test that fails without it. Security-relevant changes (policy, auth, signing, audit) need a reviewer from the maintainers.
4. Commit messages: imperative subject under 72 characters, body explaining why.
5. No real keys, tokens or customer hostnames in fixtures. Use `bank.internal` and `bank.example`.

Good first issues are the connectors and enrollment protocols listed in `docs/ROADMAP.md`; each names the interface it implements.
