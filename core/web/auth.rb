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
  plugin :render, views: File.join($root_dir, 'core/web/views/auth'),
                  engine: 'haml', layout: 'layout'
  plugin :rodauth do
    enable :login, :logout, :otp, :recovery_codes

    prefix '/auth'
    db DB                                     # bind explicitly to the existing Sequel connection
    domain { $config['web']['domain'] }       # also feeds the TOTP issuer
    hmac_secret { $config.dig('web', 'admin', 'hmac_secret') }
    title_instance_variable :@title

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
      unless RubyCA::Core::Web::AccessControl.host_allowed?(remote_addr)
        rodauth.require_authentication
      end
    end
  end

  private

  # Mirrors how the Sinatra app determines the client address
  def remote_addr
    env['HTTP_X_REAL_IP'] || env['HTTP_X_FORWARDED_FOR'] || request.ip
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
