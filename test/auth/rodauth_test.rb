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

    # Hermetic allowlist: never depend on the developer's real config.
    @original_allowed_ips = $config['web']['admin']['allowed_ips']
    $config['web']['admin']['allowed_ips'] = ['127.0.0.1']
  end

  def teardown
    $config['web']['admin']['allowed_ips'] = @original_allowed_ips
  end

  def test_allowed_ip_reaches_admin_without_login
    get '/admin'

    assert_equal 200, last_response.status
    assert_includes last_response.body, 'Welcome to RubyCA'
    assert_includes last_response.body, 'Login'
    refute_match %r{href=['"]/auth/logout}, last_response.body
    refute_match %r{Two-Factor}, last_response.body
  end

  # Settings controls the IP allowlist itself, so it must require a login
  # even for allowlisted IPs. Other admin pages keep the bypass.
  def test_config_page_requires_login_even_from_allowed_ip
    get '/admin/config'

    assert_equal 302, last_response.status
    assert_equal '/auth/login', last_response.headers['Location']

    # /admin itself is still reachable without a login from an allowed IP.
    get '/admin'
    assert_equal 200, last_response.status

    seed_admin
    post '/auth/login', {
      'login' => ADMIN_EMAIL,
      'password' => ADMIN_PASSWORD,
      '_csrf' => csrf_token(get_login_page)
    }
    assert_equal 302, last_response.status
    assert_equal '/admin/config', last_response.headers['Location'],
                 'login must return to the requested Settings page'

    get '/admin/config'
    assert_equal 200, last_response.status
    assert_match %r{>\s*Two-Factor Auth\s*<}m, last_response.body
  end

  def test_configs_alias_requires_login_even_from_allowed_ip
    get '/admin/configs'

    assert_equal 302, last_response.status
    assert_equal '/auth/login', last_response.headers['Location']
  end

  # Deep link to a Settings tab (the CRL page links here).
  def test_config_tab_deep_link_requires_login_even_from_allowed_ip
    get '/admin/config/3'

    assert_equal 302, last_response.status
    assert_equal '/auth/login', last_response.headers['Location']

    seed_admin
    post '/auth/login', {
      'login' => ADMIN_EMAIL,
      'password' => ADMIN_PASSWORD,
      '_csrf' => csrf_token(get_login_page)
    }
    assert_equal 302, last_response.status
    assert_equal '/admin/config/3', last_response.headers['Location'],
                 'login must return to the requested Settings tab'

    get '/admin/config/3'
    assert_equal 302, last_response.status
    assert_match %r{/admin/config\z}, last_response.headers['Location']

    get '/admin/config'
    assert_equal 200, last_response.status
    assert_match %r{>\s*CRL Distribution Points\s*<}m, last_response.body
    assert_includes last_response.body, 'config_crl_add_uri'
  end

  def test_crl_page_shows_distribution_points_and_links_to_settings
    get '/admin/crl'

    assert_equal 200, last_response.status
    assert_match %r{>\s*CRL Distribution Points\s*<}m, last_response.body
    assert_match %r{href=['"]/admin/config/3['"]}, last_response.body
    refute_includes last_response.body, 'cfg_crl_add_uri'
  end

  def test_config_post_requires_login_even_from_allowed_ip
    post '/admin/config', { 'tab_id' => '1' }

    assert_equal 302, last_response.status
    assert_equal '/auth/login', last_response.headers['Location']
  end

  # The Settings page must also enforce the second factor for allowlisted
  # IPs when the account has TOTP configured.
  def test_config_page_enforces_totp_even_from_allowed_ip
    seed_admin
    login_without_2fa
    secret = enroll_totp

    logout

    get '/admin/config'
    assert_equal 302, last_response.status
    assert_equal '/auth/login', last_response.headers['Location']

    post '/auth/login', {
      'login' => ADMIN_EMAIL,
      'password' => ADMIN_PASSWORD,
      '_csrf' => csrf_token(get_login_page)
    }
    assert_equal 302, last_response.status
    assert_equal '/admin/config', last_response.headers['Location']

    get '/admin/config'
    assert_equal 302, last_response.status
    assert_equal '/auth/multifactor-auth', last_response.headers['Location']

    get '/auth/multifactor-auth'
    assert_equal 302, last_response.status
    get '/auth/otp-auth'
    assert_equal 200, last_response.status

    post '/auth/otp-auth', {
      'otp' => ROTP::TOTP.new(secret).at(Time.now),
      '_csrf' => csrf_token(last_response.body)
    }
    assert_equal 302, last_response.status
    assert_equal '/admin/config', last_response.headers['Location'],
                 'TOTP authentication must return to the requested Settings page'

    get '/admin/config'
    assert_equal 200, last_response.status
    assert_match %r{>\s*Two-Factor Auth\s*<}m, last_response.body
  end

  def test_non_allowed_ip_is_redirected_to_login
    get '/admin', {}, not_allowed_env

    assert_equal 302, last_response.status
    assert_equal '/auth/login', last_response.headers['Location']

    follow_redirect!

    assert_equal 200, last_response.status
    assert_includes last_response.body, 'name="login"'
    assert_includes last_response.body, 'name="password"'

    # The login page uses layout_hide_menu: no admin navbar.
    refute_match %r{navbar-nav}, last_response.body
  end

  def test_login_succeeds_with_seeded_account
    seed_admin

    login_without_2fa

    assert_equal 200, last_response.status
    assert_includes last_response.body, 'Welcome to RubyCA'
    assert_includes last_response.body, 'Logout'
    refute_includes last_response.body, "'/auth/login'"
  end

  # The admin nav must reflect the login state: after login it offers
  # Logout, and no Login link. The Two-Factor Auth entry now lives as a
  # tab on the Settings page rather than in the navbar.
  def test_nav_shows_two_factor_and_logout_when_logged_in
    seed_admin

    login_without_2fa

    assert_match %r{href=['"]/auth/logout}, last_response.body
    assert_match %r{>\s*Logout\s*<}, last_response.body
    refute_match %r{href=['"]/auth/login}, last_response.body

    # The navbar no longer carries the standalone Two-Factor Auth link...
    refute_match %r{>\s*Two-Factor Auth\s*<}m, last_response.body

    # ...it is a Settings tab instead, offering the setup action as a
    # button while TOTP is not enrolled yet.
    get '/admin/config', {}, not_allowed_env

    assert_equal 200, last_response.status
    assert_match %r{>\s*Two-Factor Auth\s*<}m, last_response.body
    assert_match %r{href=['"]/auth/otp-setup}, last_response.body
    assert_includes last_response.body, 'Setup TOTP Auth'
    refute_includes last_response.body, 'Setup Multifactor Authentication'
  end

  # Once TOTP is enrolled, the Settings tab offers the actions an admin needs
  # afterwards: add the recovery codes (they don't exist yet after enrollment),
  # then view them once added, and disable TOTP.
  def test_settings_two_factor_tab_shows_recovery_and_disable_buttons_after_enrollment
    seed_admin
    login_without_2fa
    enroll_totp

    get '/admin/config', {}, not_allowed_env

    assert_equal 200, last_response.status
    # Recovery codes don't exist yet after TOTP enrollment: offer to add them.
    assert_match %r!href=['"]/auth/recovery-codes.+Add\s+Recovery\s+Codes!m,
                 last_response.body
    assert_match %r!href=['"]/auth/otp-disable.+Disable\s+TOTP\s+Auth!m,
                 last_response.body
    refute_includes last_response.body, 'Setup Multifactor Authentication'
    refute_includes last_response.body, 'Remove Multifactor Authentication'
    refute_match %r{href=['"]/auth/otp-setup}, last_response.body

    # Add codes, then the tab offers to view them instead.
    get '/auth/recovery-codes', {}, not_allowed_env
    assert_equal 200, last_response.status

    post '/auth/recovery-codes', {
      'password' => ADMIN_PASSWORD,
      'add' => '1',
      '_csrf' => csrf_token(last_response.body)
    }, not_allowed_env
    assert_equal 302, last_response.status
    follow_redirect!
    assert_equal 200, last_response.status
    assert_match %r{>\s*Two-Factor Auth\s*<}m, last_response.body,
                 'adding recovery codes returns to Settings > Two-Factor Auth'
    assert_match %r!href=['"]/auth/recovery-codes.+View\s+Auth\s+Recovery\s+Codes!m,
                 last_response.body

    # Clicking "View Auth Recovery Codes" and confirming the password renders
    # the codes instead of redirecting away.
    get '/auth/recovery-codes', {}, not_allowed_env
    assert_equal 200, last_response.status
    assert_match %r{name=["']password["']}, last_response.body
    assert_includes last_response.body, 'View Authentication Recovery Codes'

    post '/auth/recovery-codes', {
      'password' => ADMIN_PASSWORD,
      '_csrf' => csrf_token(last_response.body)
    }, not_allowed_env
    assert_equal 200, last_response.status,
                 'confirming password to view codes must render the codes page'
    assert_includes last_response.body, 'Your authentication recovery codes:'

    account_id = DB[:accounts].where(email: ADMIN_EMAIL).get(:id)
    refute_empty DB[:account_recovery_codes].where(id: account_id).all,
                 'recovery codes should exist'
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
    # Uses layout_hide_menu: no admin navbar.
    refute_match %r{navbar-nav}, last_response.body

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
    assert_equal 302, last_response.status
    follow_redirect!
    assert_equal 200, last_response.status
    assert_match %r{>\s*Two-Factor Auth\s*<}m, last_response.body,
                 'adding recovery codes returns to Settings > Two-Factor Auth'

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
    # Uses layout_hide_menu: no admin navbar.
    refute_match %r{navbar-nav}, last_response.body
    assert_includes last_response.body, 'Using TOTP',
                    'the TOTP second factor must be offered as a button'
    assert_includes last_response.body, 'Using Recovery Code',
                    'the recovery-code second factor must be offered as a button'

    # Follow the recovery code link and authenticate with it
    get '/auth/recovery-auth', {}, not_allowed_env
    assert_equal 200, last_response.status
    # Uses layout_hide_menu: no admin navbar.
    refute_match %r{navbar-nav}, last_response.body

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

  # Clicking "View Authentication Recovery Codes" (Settings > Two-Factor
  # Auth) used to lose the destination at every auth step: login dropped the
  # admin on /admin, then the second factor dropped them there again, so the
  # link had to be clicked three times. Login and TOTP must now return to
  # the originally requested page, where the password confirmation is asked.
  def test_recovery_codes_flow_returns_to_codes_after_login_and_totp
    seed_admin
    login_without_2fa
    secret = enroll_totp

    logout

    get '/auth/recovery-codes', {}, not_allowed_env
    assert_equal 302, last_response.status
    assert_equal '/auth/login', last_response.headers['Location']

    post '/auth/login', {
      'login' => ADMIN_EMAIL,
      'password' => ADMIN_PASSWORD,
      '_csrf' => csrf_token(get_login_page)
    }, not_allowed_env
    assert_equal 302, last_response.status
    assert_equal '/auth/recovery-codes', last_response.headers['Location'],
                 'login must return to the requested recovery-codes page'

    # Password-only session: the second factor is still required, and the
    # codes page must be remembered as the destination.
    get '/auth/recovery-codes', {}, not_allowed_env
    assert_equal 302, last_response.status
    assert_equal '/auth/multifactor-auth', last_response.headers['Location']

    get '/auth/multifactor-auth', {}, not_allowed_env
    assert_equal 302, last_response.status

    get '/auth/otp-auth', {}, not_allowed_env
    assert_equal 200, last_response.status

    post '/auth/otp-auth', {
      'otp' => ROTP::TOTP.new(secret).at(Time.now),
      '_csrf' => csrf_token(last_response.body)
    }, not_allowed_env
    assert_equal 302, last_response.status
    assert_equal '/auth/recovery-codes', last_response.headers['Location'],
                 'TOTP authentication must return to the requested recovery-codes page'

    # And the landed page asks for the password before revealing the codes.
    get '/auth/recovery-codes', {}, not_allowed_env
    assert_equal 200, last_response.status
    assert_match %r{name=["']password["']}, last_response.body
    assert_includes last_response.body, 'Add Authentication Recovery Codes'

    post '/auth/recovery-codes', {
      'password' => ADMIN_PASSWORD,
      'add' => '1',
      '_csrf' => csrf_token(last_response.body)
    }, not_allowed_env
    assert_equal 302, last_response.status
    follow_redirect!
    assert_equal 200, last_response.status
    assert_match %r{>\s*Two-Factor Auth\s*<}m, last_response.body,
                 'adding recovery codes returns to Settings > Two-Factor Auth'
  end

  # The same return-to tracking keeps deep admin links usable: a bookmarked
  # /admin/config request must survive the login and second-factor redirects.
  def test_login_and_totp_return_to_requested_admin_page
    seed_admin
    login_without_2fa
    secret = enroll_totp

    logout

    get '/admin/config', {}, not_allowed_env
    assert_equal 302, last_response.status
    assert_equal '/auth/login', last_response.headers['Location']

    post '/auth/login', {
      'login' => ADMIN_EMAIL,
      'password' => ADMIN_PASSWORD,
      '_csrf' => csrf_token(get_login_page)
    }, not_allowed_env
    assert_equal 302, last_response.status
    assert_equal '/admin/config', last_response.headers['Location'],
                 'login must return to the requested admin page'

    get '/admin/config', {}, not_allowed_env
    assert_equal 302, last_response.status
    assert_equal '/auth/multifactor-auth', last_response.headers['Location']

    get '/auth/multifactor-auth', {}, not_allowed_env
    assert_equal 302, last_response.status

    get '/auth/otp-auth', {}, not_allowed_env
    assert_equal 200, last_response.status

    post '/auth/otp-auth', {
      'otp' => ROTP::TOTP.new(secret).at(Time.now),
      '_csrf' => csrf_token(last_response.body)
    }, not_allowed_env
    assert_equal 302, last_response.status
    assert_equal '/admin/config', last_response.headers['Location'],
                 'TOTP authentication must return to the requested admin page'

    get '/admin/config', {}, not_allowed_env
    assert_equal 200, last_response.status
    assert_match %r{>\s*Two-Factor Auth\s*<}m, last_response.body
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

  # Wrong password re-renders the login form with the error flash and
  # must not authenticate the session; the account stays usable.
  def test_wrong_password_shows_error_and_does_not_authenticate
    seed_admin

    get '/admin', {}, not_allowed_env
    assert_equal 302, last_response.status

    post '/auth/login', {
      'login' => ADMIN_EMAIL,
      'password' => 'definitely not the password',
      '_csrf' => csrf_token(get_login_page)
    }, not_allowed_env

    assert_match %r{name=["']password["']}, last_response.body,
                 'login form must be re-rendered after a failed login'
    assert_includes last_response.body, 'There was an error logging in',
                    'error flash must explain the failure'

    get '/admin', {}, not_allowed_env
    assert_equal 302, last_response.status
    assert_equal '/auth/login', last_response.headers['Location']

    # The account must not have been locked or otherwise damaged.
    post '/auth/login', {
      'login' => ADMIN_EMAIL,
      'password' => ADMIN_PASSWORD,
      '_csrf' => csrf_token(get_login_page)
    }, not_allowed_env
    assert_equal 302, last_response.status

    get '/admin', {}, not_allowed_env
    assert_equal 200, last_response.status
    assert_includes last_response.body, 'Welcome to RubyCA'
  end

  # A wrong TOTP code is counted against the account (num_failures) and
  # re-renders the code form with the error flash; the backdate keeps the
  # replay filter out of the way so the failure is genuinely counted.
  def test_invalid_totp_code_is_counted_and_rejected
    seed_admin
    login_without_2fa
    account_id = DB[:accounts].where(email: ADMIN_EMAIL).get(:id)
    secret = enroll_totp

    logout
    login_without_2fa

    get '/auth/otp-auth', {}, not_allowed_env
    assert_equal 200, last_response.status

    post '/auth/otp-auth', {
      'otp' => '000000',
      '_csrf' => csrf_token(last_response.body)
    }, not_allowed_env

    assert_includes last_response.body, 'Authenticate Using TOTP',
                    'code form must be re-rendered after a wrong code'
    assert_match %r{(invalid|error)}i, last_response.body
    assert_equal 1, DB[:account_otp_keys].where(id: account_id).get(:num_failures),
                 'a wrong code must increment the failure counter'

    # The correct code (after backdating so replay protection does not
    # interfere) must still get in, and reset the failure counter.
    backdate_totp_last_use!(account_id)
    post '/auth/otp-auth', {
      'otp' => ROTP::TOTP.new(secret).at(Time.now),
      '_csrf' => csrf_token(last_response.body)
    }, not_allowed_env
    assert_equal 302, last_response.status

    get '/admin', {}, not_allowed_env
    assert_equal 200, last_response.status
    assert_equal 0, DB[:account_otp_keys].where(id: account_id).get(:num_failures),
                   'a successful code must reset the failure counter'
  end

  # A wrong recovery code must not consume any of the valid codes.
  def test_invalid_recovery_code_is_not_consumed
    seed_admin
    login_without_2fa
    account_id = DB[:accounts].where(email: ADMIN_EMAIL).get(:id)
    enroll_totp

    get '/auth/recovery-codes'
    assert_equal 200, last_response.status

    post '/auth/recovery-codes', {
      'password' => ADMIN_PASSWORD,
      'add' => '1',
      '_csrf' => csrf_token(last_response.body)
    }
    codes = DB[:account_recovery_codes].where(id: account_id).order(:code).select_map(:code)

    logout
    login_without_2fa

    get '/auth/recovery-auth', {}, not_allowed_env
    assert_equal 200, last_response.status

    post '/auth/recovery-auth', {
      'recovery-code' => 'not-a-real-code',
      '_csrf' => csrf_token(last_response.body)
    }, not_allowed_env

    assert_includes last_response.body, 'recovery-code',
                    'recovery code form must be re-rendered after a bad code'
    assert_match %r{(invalid|error)}i, last_response.body

    remaining = DB[:account_recovery_codes].where(id: account_id).select_map(:code)
    assert_equal codes.sort, remaining.sort,
                 'a bad code attempt must not consume any recovery code'
  end

  # A login POST without a CSRF token must be rejected outright, not just
  # ignored: the session must stay unauthenticated afterwards.
  def test_login_without_csrf_token_is_rejected
    seed_admin

    post '/auth/login', {
      'login' => ADMIN_EMAIL,
      'password' => ADMIN_PASSWORD
    }, not_allowed_env

    refute_equal 302, last_response.status,
                 'a tokenless login POST must not succeed'
    assert_equal 400, last_response.status

    get '/admin', {}, not_allowed_env
    assert_equal 302, last_response.status
    assert_equal '/auth/login', last_response.headers['Location']
  end

  # Disabling TOTP must remove the otp key; afterwards a login needs only
  # the password and goes straight to /admin.
  def test_otp_disable_removes_totp_and_restores_password_only_login
    seed_admin
    login_without_2fa
    account_id = DB[:accounts].where(email: ADMIN_EMAIL).get(:id)
    enroll_totp

    get '/auth/otp-disable'
    assert_equal 200, last_response.status
    assert_includes last_response.body, 'Disable TOTP Authentication'

    post '/auth/otp-disable', {
      'password' => ADMIN_PASSWORD,
      '_csrf' => csrf_token(last_response.body)
    }
    assert_equal 302, last_response.status
    assert_nil DB[:account_otp_keys].where(id: account_id).first,
               'the otp key must be gone after disabling TOTP'

    # Next login: password-only, straight to /admin.
    logout
    get '/admin', {}, not_allowed_env
    assert_equal 302, last_response.status
    assert_equal '/auth/login', last_response.headers['Location']

    post '/auth/login', {
      'login' => ADMIN_EMAIL,
      'password' => ADMIN_PASSWORD,
      '_csrf' => csrf_token(get_login_page)
    }, not_allowed_env
    assert_equal 302, last_response.status

    get '/admin', {}, not_allowed_env
    assert_equal 200, last_response.status
    assert_includes last_response.body, 'Welcome to RubyCA'
  end

  # Removing all multifactor methods must clear both the TOTP key and the
  # recovery codes, restoring password-only login.
  def test_multifactor_disable_removes_all_second_factors
    seed_admin
    login_without_2fa
    account_id = DB[:accounts].where(email: ADMIN_EMAIL).get(:id)
    enroll_totp

    get '/auth/recovery-codes'
    assert_equal 200, last_response.status
    post '/auth/recovery-codes', {
      'password' => ADMIN_PASSWORD,
      'add' => '1',
      '_csrf' => csrf_token(last_response.body)
    }
    assert_equal 302, last_response.status
    refute_empty DB[:account_recovery_codes].where(id: account_id).all

    get '/auth/multifactor-disable'
    assert_equal 200, last_response.status
    assert_includes last_response.body, 'Remove All Multifactor Authentication Methods'

    post '/auth/multifactor-disable', {
      'password' => ADMIN_PASSWORD,
      '_csrf' => csrf_token(last_response.body)
    }
    assert_equal 302, last_response.status

    assert_nil DB[:account_otp_keys].where(id: account_id).first,
               'the otp key must be gone'
    assert_empty DB[:account_recovery_codes].where(id: account_id).all,
                 'the recovery codes must be gone'

    logout
    login_without_2fa

    assert_equal 200, last_response.status
    assert_includes last_response.body, 'Welcome to RubyCA'
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
