if __FILE__ == $0 then abort 'This file forms part of RubyCA and is not designed to be called directly. Please run ./RubyCA instead.' end

require 'roda'
require 'rodauth'

module RubyCA
  module Core
    module Web
      # Shared admin access control. Allowed IPs (web.admin.allowed_ips in
      # config/rubyca.yml) bypass the login entirely; everybody else has to
      # authenticate through Rodauth before reaching /admin.
      module AccessControl
        module_function

        # Settings edits the allowlist itself (and the 2FA settings), so it
        # must require a logged-in admin even when the request comes from an
        # allowlisted IP. Other /admin pages keep the allowlist bypass.
        AUTHENTICATION_REQUIRED_ADMIN_PATHS = %w[/admin/config /admin/configs].freeze

        def admin_authentication_required?(path, addr, allowed_ips = $config['web']['admin']['allowed_ips'])
          admin_path_requires_authentication?(path) || !host_allowed?(addr, allowed_ips)
        end

        def admin_path_requires_authentication?(path)
          return false if path.nil?

          AUTHENTICATION_REQUIRED_ADMIN_PATHS.any? do |prefix|
            path == prefix || path.start_with?("#{prefix}/")
          end
        end

        def host_allowed?(addr, allowed_ips = $config['web']['admin']['allowed_ips'])
          return false if addr.nil? || allowed_ips.nil?

          begin
            ip_addr = IPAddress addr
          rescue ArgumentError
            return false
          end

          allowed_ips.each do |allowed_ip|
            begin
              allow = IPAddress allowed_ip
            rescue ArgumentError
              next
            end
            if (ip_addr.ipv4? && allow.ipv4?) || (ip_addr.ipv6? && allow.ipv6?)
              if allow.include? ip_addr
                return true
              end
            end
          end

          false
        end
      end
    end
  end
end

# Rodauth mounted as Rack middleware in front of the Sinatra app
# (RubyCA::Core::Web::Server). Handles all /auth/* routes and gates
# /admin/* for requests coming from non-allowed IPs.
class RodauthApp < Roda
  # Forward requests that this app doesn't halt (any /admin request that
  # passes the gate, unknown /auth/* paths) to the Sinatra app.
  plugin :middleware, next_if_not_found: true
  # Missing/invalid CSRF token: respond with a plain 400 page instead of
  # the default behaviour (raising RouteCsrf::InvalidToken, which surfaces
  # as a 500 to the admin).
  plugin :route_csrf do
    response.status = 400
    "<h2>Invalid request</h2><p>Missing or invalid CSRF token. Go back, reload the page and try again.</p>"
  end
  plugin :render, views: File.join($root_dir, 'core/web/views/auth'),
                  engine: 'haml',
                  layout: { path: File.join($root_dir, 'core/web/views/layout.haml') }
  plugin :rodauth do
    enable :login, :logout, :otp, :recovery_codes

    prefix '/auth'
    db DB                                     # bind explicitly to the existing Sequel connection
    domain { $config['web']['domain'] }       # also feeds the TOTP issuer
    hmac_secret { $config.dig('web', 'admin', 'hmac_secret') }
    title_instance_variable :@title

    # Keep the admin on the page they originally asked for: without these,
    # require_login / require_two_factor_authenticated drop the requested
    # path and redirect to / (which Sinatra forwards to /admin), forcing the
    # user to navigate back to e.g. the recovery-codes page after each step.
    # Rodauth only stores same-origin GET paths, so this adds no open
    # redirect surface.
    login_return_to_requested_location? true
    two_factor_auth_return_to_requested_location? true

    # Link labels on /auth/multifactor-auth render as buttons, so keep them
    # short; Rodauth uses these texts only for two_factor_auth_links.
    otp_auth_link_text 'Using TOTP'
    recovery_auth_link_text 'Using Recovery Code'

    # The login and second-factor pages (multifactor-auth, otp-auth,
    # recovery-auth) render without the admin navbar (layout_hide_menu);
    # every other auth page keeps the shared admin layout. See
    # hide_menu_view below.
    login_view do
      hide_menu_view('login', login_page_title)
    end
    two_factor_auth_view do
      hide_menu_view('two-factor-auth', two_factor_auth_page_title)
    end
    otp_auth_view do
      hide_menu_view('otp-auth', otp_auth_page_title)
    end
    recovery_auth_view do
      hide_menu_view('recovery-auth', recovery_auth_page_title)
    end

    # Don't render the login page for already authenticated admins
    already_logged_in do
      redirect '/admin'
    end

    # SQLite's CURRENT_TIMESTAMP (the account_otp_keys.last_use column
    # default) is UTC, but Sequel reads the column back as local time, so
    # right after enrollment last_use sits one UTC offset in the FUTURE.
    # rotp's replay filter (verify(code, after: last_use)) then rejects
    # every code with "Invalid authentication code" until that fake
    # future time passes. Write a consistent local timestamp instead,
    # backdated one interval so the code showing in the authenticator
    # right after enrollment can be used immediately.
    after_otp_setup do
      otp_key_ds.update(otp_keys_last_use_column => Time.now - 60)
    end

    # After TOTP setup return the admin to Settings > Two-Factor Auth (tab 2)
    # instead of /admin. `session` is the shared Rack session (SessionPool
    # wraps RodauthApp), so Sinatra's /admin/config reads session[:config]
    # and activates the Two-Factor tab.
    auth.class_eval do
      # Rodauth's own view(page, title), with a per-call override that
      # swaps in the menu-less layout.
      def hide_menu_view(page, title)
        set_title(title)
        scope.view(_view_opts(page).merge(
          layout: { path: File.join($root_dir, 'core/web/views/layout_hide_menu.haml') }
        ))
      end

      def _otp_setup_response
        session[:config] = { tab_id: 2 }
        set_notice_flash otp_setup_notice_flash
        redirect '/admin/config'
      end

      # GET /auth/recovery-codes with no codes yet: render the *add* form
      # directly instead of the "View" page (which shows no codes). Rodauth's
      # add-recovery-codes view already renders a password form whose submit
      # button reads "Add Authentication Recovery Codes".
      def recovery_codes_view
        if recovery_codes_available?
          super
        else
          view('add-recovery-codes', 'Add Authentication Recovery Codes')
        end
      end

      # After recovery codes are added, return to Settings > Two-Factor Auth
      # (tab 2) instead of re-rendering the add page. `session` is the shared
      # Rack session, so Sinatra's /admin/config reads session[:config] and
      # activates the Two-Factor tab, where "View Auth Recovery Codes" now
      # shows because codes exist.
      # When just viewing existing codes (password confirmed, no `add` param),
      # render Rodauth's add-recovery-codes template which displays the codes.
      def add_recovery_codes_view
        if param_or_nil(add_recovery_codes_param)
          session[:config] = { tab_id: 2 }
          set_notice_flash recovery_codes_added_notice_flash
          redirect '/admin/config'
        else
          super
        end
      end
    end

    # The success path has the same UTC/local mismatch: Rodauth stores
    # Sequel::CURRENT_TIMESTAMP (UTC on SQLite), so one working TOTP login
    # would poison the next one. Use a local Time.now for both the replay
    # guard and the stored value.
    otp_update_last_use do
      now = Time.now
      otp_key_ds.
        where(Sequel.date_add(otp_keys_last_use_column, :seconds => _otp_interval) < now).
        update(otp_keys_last_use_column => now) == 1
    end
  end

  route do |r|
    # Lets Sinatra reach Rodauth: the admin nav (layout.haml) and the
    # defensive before filter in core/web/server.rb both use it.
    env['rodauth'] = rodauth

    # Handles /auth/login, /auth/logout, /auth/otp-setup,
    # /auth/otp-auth, /auth/otp-disable, /auth/multifactor-manage,
    # /auth/multifactor-auth, /auth/multifactor-disable,
    # /auth/recovery-codes, /auth/recovery-auth. Rodauth matches its
    # routes against the remaining path, so the r.on wrapper consumes
    # the /auth segment; the configured prefix keeps the paths that
    # Rodauth generates (links, redirects) absolute.
    r.on 'auth' do
      r.rodauth
    end

    # Gate /admin here (and not only inside Sinatra) so that Rodauth
    # flash messages and session rotation work for the redirect to the
    # login page. Sinatra keeps an identical check as a fallback.
    r.on 'admin' do
      if RubyCA::Core::Web::AccessControl.admin_authentication_required?(request.path, remote_addr)
        rodauth.require_authentication
      end
    end
  end

  private

  # Mirrors how the Sinatra app determines the client address
  def remote_addr
    env['HTTP_X_REAL_IP'] || env['HTTP_X_FORWARDED_FOR'] || request.ip
  end

  # The shared main layout (core/web/views/layout.haml) renders auth pages
  # too and calls the Sinatra helper by this name; provide Rodauth's
  # Bootstrap-styled flash markup under that name.
  def styled_flash
    rodauth_flash_messages
  end

  # Bootstrap-styled Rodauth flash messages (Roda flash plugin) for the
  # auth layout. Follows the same markup as core/web/flash.rb.
  def rodauth_flash_messages
    ''.tap do |out|
      unless flash[:error].to_s.empty?
        out << "<div class='alert alert-dismissible alert-danger'><button type='button' class='btn-close' data-bs-dismiss='alert' aria-label='Close'></button><strong>Error: </strong>#{h flash[:error]}</div>\n"
      end
      unless flash[:notice].to_s.empty?
        out << "<div class='alert alert-dismissible alert-success'><button type='button' class='btn-close' data-bs-dismiss='alert' aria-label='Close'></button><strong>Notice: </strong>#{h flash[:notice]}</div>\n"
      end
    end
  end
end
