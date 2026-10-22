require_relative '../test_helper'
require 'rack/test'
require 'bcrypt'
require 'rotp'
require 'core/web/auth'
require 'core/web/server'

# Integration tests for the Rodauth middleware (core/web/auth.rb) that
# protects /admin. Note the DB-rebinding gotcha from AGENTS.md applies:
# core/web/auth.rb binds Rodauth to the file-based db/rubyca-test.db.
class RodauthTest < Minitest::Test
  include Rack::Test::Methods

  ADMIN_EMAIL = 'rodauth-admin@example.com'
  ADMIN_PASSWORD = 'correct horse battery staple'
  NOT_ALLOWED_IP = '203.0.113.50'

  def app
    @app ||= RubyCA::Core::Web::Server.new
  end

  def setup
    RubyCA::Core::Web::Server.set :show_exceptions, false
    DB[:account_otp_keys].delete
    DB[:account_recovery_codes].delete
    DB[:account_password_hashes].delete
    DB[:accounts].delete
  end

  def test_allowed_ip_reaches_admin_without_login
    get '/admin'

    assert_equal 200, last_response.status
    assert_includes last_response.body, 'Welcome to RubyCA'
    assert_includes last_response.body, 'Login'
  end

  def test_non_allowed_ip_is_redirected_to_login
    get '/admin', {}, not_allowed_env

    assert_equal 302, last_response.status
    assert_equal '/auth/login', last_response.headers['Location']

    follow_redirect!

    assert_equal 200, last_response.status
    assert_includes last_response.body, 'name="login"'
    assert_includes last_response.body, 'name="password"'
  end

  def test_login_succeeds_with_seeded_account
    seed_admin

    login_without_2fa

    assert_equal 200, last_response.status
    assert_includes last_response.body, 'Welcome to RubyCA'
    assert_includes last_response.body, 'Logout'
    refute_includes last_response.body, "'/auth/login'"
  end

  def test_totp_enrollment_and_auth_round_trip
    seed_admin
    login_without_2fa

    # Enroll TOTP
    get '/auth/otp-setup'
    assert_equal 200, last_response.status

    secret = hidden_field(last_response.body, 'otp_secret')
    refute_nil secret, 'otp-setup page should expose the secret to confirm'
    code = ROTP::TOTP.new(secret).at(Time.now)

    post '/auth/otp-setup', otp_setup_params(last_response.body, code)
    assert_equal 302, last_response.status

    account_id = DB[:accounts].where(email: ADMIN_EMAIL).get(:id)
    refute_nil DB[:account_otp_keys].where(id: account_id).first, 'TOTP key should be stored'

    # Logging out and back in must now require the second factor, and a
    # code generated right now must work: enrollment must not leave a
    # last_use that reads back in the future (the SQLite CURRENT_TIMESTAMP
    # column default is UTC while the app reads local time, which makes
    # replay protection reject every code with "Invalid authentication
    # code").
    logout
    get '/admin', {}, not_allowed_env
    assert_equal 302, last_response.status
    assert_equal '/auth/login', last_response.headers['Location']

    post '/auth/login', {
      'login' => ADMIN_EMAIL,
      'password' => ADMIN_PASSWORD,
      '_csrf' => csrf_token(get_login_page)
    }
    assert_equal 302, last_response.status

    get '/admin', {}, not_allowed_env
    assert_equal 302, last_response.status
    assert_equal '/auth/multifactor-auth', last_response.headers['Location']

    # With a single second factor configured, the multifactor-auth page
    # redirects straight to the TOTP code entry form.
    get '/auth/multifactor-auth', {}, not_allowed_env
    assert_equal 302, last_response.status
    get '/auth/otp-auth', {}, not_allowed_env
    assert_equal 200, last_response.status
    assert_includes last_response.body, 'Authenticate Using TOTP'

    post '/auth/otp-auth', {
      'otp' => ROTP::TOTP.new(secret).at(Time.now),
      '_csrf' => csrf_token(last_response.body)
    }, not_allowed_env
    assert_equal 302, last_response.status

    get '/admin', {}, not_allowed_env
    assert_equal 200, last_response.status
    assert_includes last_response.body, 'Welcome to RubyCA'

    # The successful login must leave a consistent last_use behind (a UTC
    # CURRENT_TIMESTAMP would read hours in the future and break the next
    # login). Simulate coming back later and log in a second time.
    last_use = DB[:account_otp_keys].where(id: account_id).get(:last_use)
    assert_operator last_use, :<=, Time.now + 1,
                    'last_use after login must not be in the future'

    backdate_totp_last_use!(account_id)
    logout
    post '/auth/login', {
      'login' => ADMIN_EMAIL,
      'password' => ADMIN_PASSWORD,
      '_csrf' => csrf_token(get_login_page)
    }
    assert_equal 302, last_response.status

    get '/auth/otp-auth', {}, not_allowed_env
    assert_equal 200, last_response.status
    assert_includes last_response.body, 'Authenticate Using TOTP'

    post '/auth/otp-auth', {
      'otp' => ROTP::TOTP.new(secret).at(Time.now),
      '_csrf' => csrf_token(last_response.body)
    }, not_allowed_env
    assert_equal 302, last_response.status

    get '/admin', {}, not_allowed_env
    assert_equal 200, last_response.status
    assert_includes last_response.body, 'Welcome to RubyCA'
  end

  def test_recovery_codes_are_available_after_totp_setup
    seed_admin
    login_without_2fa

    enroll_totp

    # Still fully authenticated (the TOTP setup authenticated this
    # session): add recovery codes from the manage page.
    get '/auth/multifactor-manage'
    assert_equal 200, last_response.status
    assert_includes last_response.body, 'Multifactor Authentication'

    # Follow the manage page link to the recovery codes form, then add codes
    get '/auth/recovery-codes'
    assert_equal 200, last_response.status

    post '/auth/recovery-codes', {
      'password' => ADMIN_PASSWORD,
      'add' => '1',
      '_csrf' => csrf_token(last_response.body)
    }
    assert_equal 200, last_response.status
    assert_includes last_response.body, 'Your authentication recovery codes:'

    account_id = DB[:accounts].where(email: ADMIN_EMAIL).get(:id)
    codes = DB[:account_recovery_codes].where(id: account_id).order(:code).select_map(:code)
    refute_empty codes, 'recovery codes should be generated'

    # Recovery code must work as second factor at login
    logout
    get '/admin', {}, not_allowed_env
    assert_equal 302, last_response.status
    assert_equal '/auth/login', last_response.headers['Location']

    post '/auth/login', {
      'login' => ADMIN_EMAIL,
      'password' => ADMIN_PASSWORD,
      '_csrf' => csrf_token(get_login_page)
    }
    assert_equal 302, last_response.status

    get '/admin', {}, not_allowed_env
    assert_equal 302, last_response.status
    assert_equal '/auth/multifactor-auth', last_response.headers['Location']

    get '/auth/multifactor-auth', {}, not_allowed_env
    assert_equal 200, last_response.status
    assert_includes last_response.body, 'Authenticate Using Additional Factor'

    # Follow the recovery code link and authenticate with it
    get '/auth/recovery-auth', {}, not_allowed_env
    assert_equal 200, last_response.status

    post '/auth/recovery-auth', {
      'recovery-code' => codes.first,
      '_csrf' => csrf_token(last_response.body)
    }, not_allowed_env
    assert_equal 302, last_response.status

    get '/admin', {}, not_allowed_env
    assert_equal 200, last_response.status
    assert_includes last_response.body, 'Welcome to RubyCA'

    # A used recovery code must be gone
    used = DB[:account_recovery_codes].where(id: account_id, code: codes.first).first
    assert_nil used, 'used recovery code should be removed'
  end

  # When the only second factor (TOTP) is locked out after too many failed
  # codes, Rodauth hides its link from the multifactor-auth page. The page
  # must explain the dead end instead of leaving the admin stuck with no
  # way forward and no indication why.
  def test_locked_out_totp_shows_lockout_explanation_on_multifactor_page
    seed_admin
    login_without_2fa
    account_id = DB[:accounts].where(email: ADMIN_EMAIL).get(:id)
    enroll_totp

    # Rodauth hides the TOTP link once num_failures reaches the
    # otp_auth_failures_limit (default 5) and the lockout never expires.
    DB[:account_otp_keys].where(id: account_id).update(num_failures: 5)

    logout
    get '/admin', {}, not_allowed_env
    assert_equal 302, last_response.status
    assert_equal '/auth/login', last_response.headers['Location']

    post '/auth/login', {
      'login' => ADMIN_EMAIL,
      'password' => ADMIN_PASSWORD,
      '_csrf' => csrf_token(get_login_page)
    }
    assert_equal 302, last_response.status

    get '/admin', {}, not_allowed_env
    assert_equal 302, last_response.status
    assert_equal '/auth/multifactor-auth', last_response.headers['Location']

    # No second factor is offered, so the page renders (no redirect to an
    # auth form is possible); it must explain the lockout and the way out,
    # and must not link the unusable TOTP form.
    get '/auth/multifactor-auth', {}, not_allowed_env
    assert_equal 200, last_response.status
    assert_includes last_response.body, 'Authenticate Using Additional Factor'
    assert_includes last_response.body, 'TOTP authentication is locked out'
    assert_includes last_response.body, 'rodauth:reset_totp_lockout'
    refute_includes last_response.body, '/auth/otp-auth'
  end

  private

  def not_allowed_env
    { 'HTTP_X_FORWARDED_FOR' => NOT_ALLOWED_IP }
  end

  # Seeds an admin account the way `rake rodauth:create_admin` does
  def seed_admin
    id = DB[:accounts].insert(email: ADMIN_EMAIL, status_id: 2)
    DB[:account_password_hashes].insert(
      id: id,
      password_hash: BCrypt::Password.create(ADMIN_PASSWORD, cost: 4)
    )
  end

  def get_login_page
    get '/auth/login', {}, not_allowed_env
    assert_equal 200, last_response.status
    last_response.body
  end

  # Logs in from an non-allowed IP, following up to the original target
  # (/admin), which must be reachable afterwards.
  def login_without_2fa
    get '/admin', {}, not_allowed_env
    assert_equal 302, last_response.status
    assert_equal '/auth/login', last_response.headers['Location']

    post '/auth/login', {
      'login' => ADMIN_EMAIL,
      'password' => ADMIN_PASSWORD,
      '_csrf' => csrf_token(get_login_page)
    }
    assert_equal 302, last_response.status

    get '/admin', {}, not_allowed_env
  end

  def logout
    get '/auth/logout'
    assert_equal 200, last_response.status

    post '/auth/logout', '_csrf' => csrf_token(last_response.body)
    assert_equal 302, last_response.status
  end

  # Enrolls TOTP for the logged in admin and returns the (possibly
  # HMACed) user key, mirroring what the otp-setup form submits.
  def enroll_totp
    get '/auth/otp-setup'
    assert_equal 200, last_response.status

    secret = hidden_field(last_response.body, 'otp_secret')
    refute_nil secret

    post '/auth/otp-setup',
      otp_setup_params(last_response.body, ROTP::TOTP.new(secret).at(Time.now))
    assert_equal 302, last_response.status
    secret
  end

  # Submits the otp-setup form the way a browser would: all hidden
  # fields present on the page plus password and confirmation code.
  def otp_setup_params(body, code)
    params = { 'password' => ADMIN_PASSWORD, 'otp' => code }
    ['otp_secret', 'otp_raw_secret', '_csrf'].each do |field|
      if (value = hidden_field(body, field))
        params[field] = value
      end
    end
    params
  end

  def csrf_token(body)
    input_tag(body, '_csrf')&.then { |tag| tag[%r{value=["']([^"']+)["']}, 1] }
  end

  # Pretend one interval passed since the last use: the code just used is
  # refused within the same interval (replay protection), and tests run
  # faster than the 30s window.
  def backdate_totp_last_use!(account_id)
    DB[:account_otp_keys].where(id: account_id)
      .update(last_use: Time.now - 60)
  end

  def hidden_field(body, name)
    input_tag(body, name)&.then { |tag| tag[%r{value=["']([^"']+)["']}, 1] }
  end

  # Haml reorders attributes, so match the whole tag instead of
  # assuming name= and value= are adjacent.
  def input_tag(body, name)
    body[%r{<input[^>]*name=["']#{Regexp.escape(name)}["'][^>]*>}]
  end
end
