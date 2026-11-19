require_relative 'task_header'

namespace :rodauth do

  # Loads the app and the shared account helpers (tasks/rodauth_accounts.rb).
  # Kept inside the tasks so `rake -T` and unrelated tasks don't load the app.
  def self.load_accounts
    require 'core/load'
    require 'core/bootstrap'
    require_relative 'rodauth_accounts'
  end

  desc "Create an admin account (prompts for email and password)"
  task :create_admin do
    load_accounts
    begin
      email = RodauthAccounts.ask_email
      RodauthAccounts.create(email, RodauthAccounts.ask_new_password)
    rescue RodauthAccounts::Error => e
      abort e.message
    end
    puts "Admin account '#{email}' created."
  end

  desc "Reset the TOTP lockout for an admin (prompts for email)"
  task :reset_totp_lockout do
    load_accounts
    begin
      email = RodauthAccounts.ask_email
      RodauthAccounts.reset_totp_lockout(RodauthAccounts.find_id!(email), email)
    rescue RodauthAccounts::Error => e
      abort e.message
    end
    puts "TOTP lockout reset for '#{email}'. Log in again using a fresh code."
  end

  desc "Remove all second-factor methods for an admin (prompts for email)"
  task :disable_totp do
    load_accounts
    begin
      email = RodauthAccounts.ask_email
      removed = RodauthAccounts.disable_two_factor(RodauthAccounts.find_id!(email))
    rescue RodauthAccounts::Error => e
      abort e.message
    end
    puts RodauthAccounts.disable_two_factor_message(email, *removed)
  end

  desc "Interactively manage admin accounts (list, add, change email/password, delete, 2FA rescue)"
  task :manage_accounts do
    load_accounts
    menu = <<~MENU

      [l] List accounts           [a] Add account
      [p] Change password         [e] Change email
      [r] Reset TOTP lockout      [t] Disable 2FA (TOTP + recovery codes)
      [d] Delete account          [q] Quit
    MENU

    print_accounts = lambda do
      accounts = RodauthAccounts.list
      if accounts.empty?
        puts 'No admin accounts. Use [a] to add one.'
      else
        puts format('%-4s %-40s %-10s %s', 'ID', 'Email', 'Status', 'Second factor')
        accounts.each do |a|
          two_factor = if a[:totp]
                         "TOTP (#{a[:otp_failures]} failure(s)), #{a[:recovery_codes]} recovery code(s)"
                       elsif a[:recovery_codes] > 0
                         "#{a[:recovery_codes]} recovery code(s)"
                       else
                         'none (password only)'
                       end
          puts format('%-4d %-40s %-10s %s', a[:id], a[:email], a[:status], two_factor)
        end
      end
    end

    puts 'RubyCA admin account management'
    print_accounts.call

    loop do
      puts menu
      choice = RodauthAccounts.ask('Choice: ')
      break if choice.nil? # EOF
      choice = choice.strip.downcase

      begin
        case choice
        when 'l'
          print_accounts.call
        when 'a'
          email = RodauthAccounts.ask_email
          RodauthAccounts.create(email, RodauthAccounts.ask_new_password)
          puts "Admin account '#{email}' created."
        when 'p'
          email = RodauthAccounts.ask_email
          id = RodauthAccounts.find_id!(email)
          RodauthAccounts.change_password(id, RodauthAccounts.ask_new_password("New password for '#{email}' (input is hidden):"))
          puts "Password changed for '#{email}'."
        when 'e'
          email = RodauthAccounts.ask_email('Current email: ')
          id = RodauthAccounts.find_id!(email)
          new_email = RodauthAccounts.ask_email('New email: ')
          RodauthAccounts.change_email(id, new_email)
          puts "Email changed from '#{email}' to '#{new_email}'."
        when 'r'
          email = RodauthAccounts.ask_email
          RodauthAccounts.reset_totp_lockout(RodauthAccounts.find_id!(email), email)
          puts "TOTP lockout reset for '#{email}'. Log in again using a fresh code."
        when 't'
          email = RodauthAccounts.ask_email
          removed = RodauthAccounts.disable_two_factor(RodauthAccounts.find_id!(email))
          puts RodauthAccounts.disable_two_factor_message(email, *removed)
        when 'd'
          email = RodauthAccounts.ask_email
          id = RodauthAccounts.find_id!(email)
          if DB[:accounts].count == 1
            puts 'WARNING: this is the last admin account. Without one, nobody can log in ' \
                 'to Settings (/admin/config), even from allowlisted IPs.'
          end
          confirm = RodauthAccounts.ask("Type '#{email}' again to confirm deletion: ").to_s.strip
          if confirm == email
            RodauthAccounts.delete(id)
            puts "Admin account '#{email}' deleted."
          else
            puts 'Confirmation did not match; nothing deleted.'
          end
        when 'q', 'quit', 'exit'
          break
        when ''
          next
        else
          puts "Unknown choice '#{choice}'."
        end
      rescue RodauthAccounts::Error => e
        puts "Error: #{e.message}"
      end
    end
    puts 'Bye.'
  end

  desc "Generate and store web.admin.hmac_secret in config/rubyca.yml"
  task :generate_hmac_secret do
    require 'core/load'
    require 'securerandom'

    unless $config.dig('web', 'admin', 'hmac_secret').to_s.empty?
      abort 'web.admin.hmac_secret is already set in config/rubyca.yml. Remove it first if you want to generate a new one.'
    end

    # Rodauth derives the TOTP secret from the stored key with HMAC once a
    # secret is set, so keys enrolled without one would stop matching every
    # authenticator app and lock those admins out.
    require 'core/bootstrap'
    enrolled = DB[:account_otp_keys].join(:accounts, id: :id).select_map(Sequel[:accounts][:email])
    unless enrolled.empty?
      abort "TOTP is enrolled without an HMAC secret for: #{enrolled.join(', ')}.\n" \
            'Setting a secret now would invalidate those authenticators. Run ' \
            '`rake rodauth:disable_totp` for each account first, generate the secret, ' \
            'restart RubyCA, then re-enroll TOTP from Settings > Two-Factor Auth.'
    end

    secret = SecureRandom.base64(64)
    $config['web']['admin'] ||= {}
    $config['web']['admin']['hmac_secret'] = secret

    File.open(CFG_FILE, 'w') {|f| YAML.dump($config, f) } #Store
    $config = YAML.load(File.read(CFG_FILE)) # Reload

    puts "HMAC secret stored in #{CFG_FILE} (web.admin.hmac_secret)."
    puts 'Restart RubyCA for the change to take effect.'
  end
end
