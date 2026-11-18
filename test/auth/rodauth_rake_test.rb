require_relative '../test_helper'
require 'rake'
require 'io/console'
require 'bcrypt'

# Loads every tasks/*.rake the same way `rake` does (the rodauth tasks
# require core/load/core/bootstrap internally; those are already loaded
# by test_helper, so DB stays the file db/rubyca-test.db, same as the
# other auth tests).
Rake.application.init
Rake.application.load_rakefile

# Tests for the rodauth:* rake tasks (tasks/rodauth.rake). The tasks read
# from STDIN (email / password prompts), so the tests swap in a fake
# stdin and capture stdout/stderr. The generate_hmac_secret task writes
# to the real config file, so only its no-overwrite guard is exercised.
class RodauthRakeTest < Minitest::Test
  ADMIN_EMAIL = 'rake-admin@example.com'
  ADMIN_PASSWORD = 'correct horse battery staple'

  def setup
    DB[:account_otp_keys].delete
    DB[:account_recovery_codes].delete
    DB[:account_password_hashes].delete
    DB[:accounts].delete
  end

  def test_create_admin_inserts_account_and_password_hash
    output, status = run_task('rodauth:create_admin',
                              ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_PASSWORD)

    assert_equal 0, status, "task failed: #{output}"

    account = DB[:accounts].where(email: ADMIN_EMAIL).first
    refute_nil account, 'the account must be created'
    assert_equal 2, account[:status_id], 'the account must be Verified'

    hash_row = DB[:account_password_hashes].where(id: account[:id]).first
    refute_nil hash_row, 'a password hash must be stored'
    assert BCrypt::Password.new(hash_row[:password_hash]) == ADMIN_PASSWORD,
           'the stored hash must verify against the prompted password'
    assert_includes output, "Admin account '#{ADMIN_EMAIL}' created."
  end

  def test_create_admin_aborts_on_blank_email
    output, status = run_task('rodauth:create_admin', '', ADMIN_PASSWORD, ADMIN_PASSWORD)

    assert_equal 1, status
    assert_includes output, 'Email cannot be blank.'
    assert_empty DB[:accounts].all
  end

  def test_create_admin_aborts_on_mismatched_passwords
    output, status = run_task('rodauth:create_admin', ADMIN_EMAIL, 'one', 'two')

    assert_equal 1, status
    assert_includes output, 'Password and confirm password do not match.'
    assert_empty DB[:accounts].all
  end

  def test_create_admin_aborts_on_blank_password
    output, status = run_task('rodauth:create_admin', ADMIN_EMAIL, '', '')

    assert_equal 1, status
    assert_includes output, 'Password cannot be blank.'
    assert_empty DB[:accounts].all
  end

  def test_create_admin_aborts_on_duplicate_email
    seed_admin(ADMIN_EMAIL)

    output, status = run_task('rodauth:create_admin',
                              ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_PASSWORD)

    assert_equal 1, status
    assert_includes output, "An account for '#{ADMIN_EMAIL}' already exists."
    assert_equal 1, DB[:accounts].where(email: ADMIN_EMAIL).count,
                 'no second account must be created'
  end

  def test_reset_totp_lockout_zeroes_failures_and_repairs_last_use
    seed_admin
    account_id = DB[:accounts].where(email: ADMIN_EMAIL).get(:id)
    # A poisoned key: locked out, with a UTC-style future last_use.
    DB[:account_otp_keys].insert(
      id: account_id, key: 'a' * 32,
      num_failures: 5, last_use: Time.now + 3600
    )

    output, status = run_task('rodauth:reset_totp_lockout', ADMIN_EMAIL)

    assert_equal 0, status, "task failed: #{output}"

    key = DB[:account_otp_keys].where(id: account_id).first
    assert_equal 0, key[:num_failures], 'the failure counter must be zeroed'
    assert_operator key[:last_use], :<=, Time.now + 1,
                    'last_use must be repaired to a local (non-future) timestamp'
    refute_nil key[:key], 'TOTP itself must be kept'
    assert_includes output, "TOTP lockout reset for '#{ADMIN_EMAIL}'."
  end

  def test_reset_totp_lockout_aborts_on_unknown_email
    output, status = run_task('rodauth:reset_totp_lockout', 'nobody@example.com')

    assert_equal 1, status
    assert_includes output, "No admin account found for 'nobody@example.com'."
  end

  def test_reset_totp_lockout_aborts_when_totp_not_configured
    seed_admin

    output, status = run_task('rodauth:reset_totp_lockout', ADMIN_EMAIL)

    assert_equal 1, status
    assert_includes output, "has no TOTP key configured."
  end

  def test_disable_totp_removes_all_second_factors
    seed_admin
    account_id = DB[:accounts].where(email: ADMIN_EMAIL).get(:id)
    DB[:account_otp_keys].insert(id: account_id, key: 'a' * 32, num_failures: 0, last_use: Time.now)
    DB[:account_recovery_codes].insert(id: account_id, code: 'aaaa-bbbb')
    DB[:account_recovery_codes].insert(id: account_id, code: 'cccc-dddd')

    output, status = run_task('rodauth:disable_totp', ADMIN_EMAIL)

    assert_equal 0, status, "task failed: #{output}"
    assert_nil DB[:account_otp_keys].where(id: account_id).first
    assert_empty DB[:account_recovery_codes].where(id: account_id).all
    assert_includes output, "Second-factor methods removed for '#{ADMIN_EMAIL}'"
    assert_includes output, '(1 TOTP key(s), 2 recovery code(s))'
    assert_includes output, 'Password-only login is restored.'
  end

  def test_disable_totp_reports_nothing_to_remove
    seed_admin

    output, status = run_task('rodauth:disable_totp', ADMIN_EMAIL)

    assert_equal 0, status, "task failed: #{output}"
    assert_includes output, 'has no second-factor methods configured'
  end

  def test_disable_totp_aborts_on_unknown_email
    output, status = run_task('rodauth:disable_totp', 'nobody@example.com')

    assert_equal 1, status
    assert_includes output, "No admin account found for 'nobody@example.com'."
  end

  # The happy path of generate_hmac_secret overwrites config/rubyca.yml
  # (the developer's real, gitignored config), so only the no-overwrite
  # guard is tested here: it must abort before touching the file.
  def test_generate_hmac_secret_refuses_to_overwrite_existing_secret
    config_path = File.join($root_dir, 'config/rubyca.yml')
    before = File.binread(config_path)

    $config['web']['admin'] ||= {}
    $config['web']['admin']['hmac_secret'] = 'existing-secret'

    output, status = run_task('rodauth:generate_hmac_secret')

    assert_equal 1, status
    assert_includes output, 'web.admin.hmac_secret is already set'
    assert_equal before, File.binread(config_path),
                 'the config file must not be touched by the guard'
  end

  private

  # Seeds an admin account the way `rake rodauth:create_admin` does
  def seed_admin(email = ADMIN_EMAIL)
    id = DB[:accounts].insert(email: email, status_id: 2)
    DB[:account_password_hashes].insert(
      id: id,
      password_hash: BCrypt::Password.create(ADMIN_PASSWORD, cost: 4)
    )
    id
  end

  # Runs a rake task with the given stdin lines; returns [output, status].
  # status is 0 unless the task aborted (SystemExit, as `abort` does).
  def run_task(name, *stdin_lines)
    output = nil
    status = 0

    with_stdin(*stdin_lines) do
      with_captured_output do
        begin
          task = Rake::Task[name]
          task.reenable
          task.invoke
        rescue SystemExit => e
          status = e.status
        end
        output = $output_sink.string + $error_sink.string
      end
    end

    [output, status]
  end

  def with_stdin(*lines)
    fake = FakeStdin.new(*lines)
    original = Object.const_get(:STDIN)
    Object.send(:remove_const, :STDIN)
    Object.const_set(:STDIN, fake)
    yield
  ensure
    Object.send(:remove_const, :STDIN)
    Object.const_set(:STDIN, original)
  end

  def with_captured_output
    stdout, stderr, output_sink, error_sink = $stdout, $stderr, StringIO.new, StringIO.new
    $output_sink, $error_sink = output_sink, error_sink
    $stdout, $stderr = output_sink, error_sink
    yield
  ensure
    $stdout, $stderr, $output_sink, $error_sink = stdout, stderr, nil, nil
  end

  # Minimal STDIN double: task code calls STDIN.gets and
  # STDIN.noecho { |s| s.gets } for hidden input.
  class FakeStdin
    def initialize(*lines)
      @lines = lines.dup
    end

    def gets
      @lines.shift
    end

    def noecho
      yield self
    end
  end
end
