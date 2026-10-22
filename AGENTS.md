# AGENTS.md

Sinatra-based certificate authority web app (no Rails): modular `Sinatra::Base`, Sequel + SQLite, Haml views, Puma server. Fork of phillcampbell/RubyCA for internal use.

## Setup (fresh clone — several required files are gitignored)

- `bundle install` — gems vendored to `vendor/bundle` (`.bundle/config` sets `BUNDLE_PATH`).
- `cp sample.env .env` — sets `APP_ENV`; the DB file is keyed on it: `db/rubyca-#{APP_ENV}.db`.
- `cp config/rubyca.yml.sample config/rubyca.yml` — app aborts at boot without it; loaded into global `$config`.
- `bundle exec rake db:migrate`.
- Ruby 4.0.3 expected. `.ruby-version` is gitignored; `utils/set_ruby_version` points PATH at Homebrew `ruby@4`.

## Commands

- Run app: `./RubyCA` (admin UI at `http://host:port/admin`).
- First run must generate the CA as root (`sudo ./RubyCA` / `sudo bundle exec rake ca:setup`) or explicitly unsafe (`./RubyCA --unsafe` / `bundle exec rake "ca:setup[unsafe]"`). Writes encrypted `private/root_ca.pem` (mode 0400); key passwords are prompted on stdin and never stored.
- Configured web port < 1024 requires root on every start (see `./RubyCA` check).
- CA maintenance: `rake ca:renew_root_certificate`, `rake ca:renew_intermediate_certificate` (prompt for key passwords on stdin).
- Admin accounts: `rake rodauth:create_admin` (prompts for email + password on a TTY, like the CA key prompts) and `rake rodauth:generate_hmac_secret` (writes `web.admin.hmac_secret` into `config/rubyca.yml`; refuses to overwrite an existing secret). TOTP rescue tasks (prompt for email on stdin): `rake rodauth:reset_totp_lockout` (zeroes the failure counter and repairs `last_use`, keeping TOTP) and `rake rodauth:disable_totp` (drops TOTP + recovery codes, restoring password-only login).
- Migrations: `rake db:generate_migration[name]`, `db:migrate`, `db:rollback[target]`, `db:reset`. Note `rake db:version` always prints 0 — it reads `schema_info`, but timestamped migrations use `schema_migrations`. Also `db:rollback`/`db:reset` are currently broken (`NameError: uninitialized constant DB` — they never open a connection); edit the DB manually or re-migrate instead.
- Version: `rake version:current` / `rake version:bump[major|minor|patch]` — writes the `version` file (read into `RUBYCA_VERSION` at boot).
- Puma daemon deploy: `cp distrib/puma/puma-sample.rb config/puma.rb`, `rake deploy:puma_directories` (creates `tmp/sockets`, `tmp/pids`, etc.), `bundle exec puma -C config/puma.rb`. systemd units in `distrib/*/init/`.
- Legacy 2.x DataMapper import: `rake db:migrate_dm_to_sequel` then `rake db:migrate_dm_crls_to_sequel` (source is the root-level `RubyCA.db`).

## Tests

- Minitest; there is no `rake test` task. Run each file directly: `bundle exec ruby test/models/certificate_test.rb`.
- Auth integration tests: `bundle exec ruby test/auth/rodauth_test.rb` (Minitest + Rack::Test; covers the IP-allowlist bypass, login redirect, password login, TOTP enrollment + 2FA round-trip (immediate login after enrollment and a second round after a success), the TOTP lockout explanation page, and recovery codes; seeds its own admin in `DB`). Note `account_otp_keys.last_use` must hold *local* timestamps: SQLite's `CURRENT_TIMESTAMP` (the column default) is UTC while Sequel reads the column as local time, so a future `last_use` makes rotp's replay filter reject every code with "Invalid authentication code" — the cause of the original TOTP lockout. `core/web/auth.rb` normalizes both write paths (`after_otp_setup` backdates at enrollment, `otp_update_last_use` writes `Time.now`); the tests cover it without manual backdating.
- Prerequisite (once): `APP_ENV=test bundle exec rake db:migrate`. Reason: `test_helper.rb` migrates an in-memory DB and sets `Sequel::Model.db` to it (models use it), but requiring `core/bootstrap` rebinds the `DB` constant to the file `db/rubyca-test.db`, so raw `DB[:table]` calls in tests hit the file DB — without the migration they fail with `no such table`.
- Tests abort without a `config/rubyca.yml` (required by `core/load`); the auth tests read the real config's `allowed_ips`/`hmac_secret`, so a config where `127.0.0.1` is allowed is assumed.
- Suite state (test/ was uncommitted WIP as of Oct 2026): `test/models/certificate_test.rb`, `test/ca/ca_setup_test.rb`, `test/ca/fill_console_test.rb`, `test/auth/rodauth_test.rb` pass; `test/ca/setup_test.rb` fails, `test/ca/my_fill_console_test.rb` errors. Don't treat those as regressions without checking.

## Architecture / wiring

- Entrypoints are `./RubyCA` and `config.ru`. Both set `$root_dir` then require `core/load` → `core/bootstrap` (→ `core/ca/setup` for the CLI). Files in `core/` abort if executed directly (`if __FILE__ == $0`) and depend on this load order — don't require models or `core/ca/setup` before `core/load`/`core/bootstrap` (they rely on globals `$config`, `$root_dir`, `$default_cipher`, `DB`).
- `core/load.rb`: Bundler.require, dotenv, loads config into `$config`, sets `$default_cipher` (default `AES-256-CBC`).
- `core/bootstrap.rb`: opens `DB` (SQLite, log at `log/db-#{APP_ENV}.log`) and requires models in `core/models/` (thin `Sequel::Model` classes; `certificates` ↔ `crls` is one-to-one, `cn` unique).
- `core/ca/setup.rb`: CA generation/renewal as top-level methods (`first_run_setup`, `gen_self_signed_root`, `create_crl`, `renew_*`); the `ca:*` rake tasks require this file directly.
- Web: all routes live in the single class in `core/web/server.rb`, mostly under `/admin/...`; Haml views in `core/web/views/`, vendored Bootstrap/Popper in `core/web/public/`. `/admin` is gated by `web.admin.allowed_ips` in config (allowed IPs bypass login entirely).
- Admin auth: Rodauth (2.x) as Rack middleware — `RodauthApp` in `core/web/auth.rb`, required after `core/bootstrap` and before `core/web/server` in both entrypoints, then `use`d by Sinatra after `Rack::Session::Pool`. Login + optional TOTP 2FA + recovery codes under `/auth/*`, Haml views in `core/web/views/auth/` overriding Rodauth's built-in templates. The `/admin` gate lives in the middleware route block (so Rodauth's flash/session rotation work on the login redirect); Sinatra's `before '/admin*'` keeps an identical check as a fallback. `host_allowed?` is shared via `RubyCA::Core::Web::AccessControl` (auth.rb); the old config basic auth (SHA256 hashes, `protected!`/`authorized?`) is gone. Rodauth binds explicitly to the `DB` constant, so the test-rebinding gotcha applies to it too. Rodauth's `otp` feature needs `rotp` AND `rqrcode` at runtime. `account_otp_keys.last_use` is written as local `Time.now` (`after_otp_setup` and `otp_update_last_use` overrides in auth.rb): the column default `CURRENT_TIMESTAMP` is UTC on SQLite and reads back the UTC offset into the future, which makes rotp's replay filter reject every TOTP code.
- `core/privileges.rb` monkey-patches EventMachine to drop privileges after binding a port (Thin legacy); Puma is the default server now.
- `core/aux.rb#legacy_pkcs12` shells out to the `openssl` CLI via `spawn` — the openssl binary is a runtime dependency for legacy PKCS#12 export.

## Gotchas

- `.gitignore` hides operational files: `config/rubyca.yml`, `.env*`, `private/`, `*.db`, `.ruby-version`, `Gemfile.lock`, `vendor/`, `bak/`. Never commit keys/DBs/env files; presence on disk does not mean they're tracked.
- `Gemfile.lock` is gitignored, so dependency resolution floats within Gemfile constraints — don't assume the local lockfile reflects the repo.
