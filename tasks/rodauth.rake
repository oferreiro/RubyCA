require_relative 'task_header'

namespace :rodauth do

  desc "Create an admin account (prompts for email and password)"
  task :create_admin do
    require 'core/load'
    require 'core/bootstrap'
    require 'io/console'
    require 'bcrypt'

    print 'Admin email: '
    email = STDIN.gets.to_s.chomp
    abort 'Email cannot be blank.' if email.empty?

    puts 'Admin password (input is hidden):'
    print 'Password: '
    password = STDIN.noecho(&:gets).to_s.chomp
    puts ''
    print 'Confirm password: '
    confirm_password = STDIN.noecho(&:gets).to_s.chomp
    puts ''

    abort 'Password cannot be blank.' if password.empty?
    abort 'Password and confirm password do not match.' unless password == confirm_password

    password_hash = BCrypt::Password.create(password)

    begin
      # status_id 2 = Verified (see account_statuses table)
      id = DB[:accounts].insert(email: email, status_id: 2)
      DB[:account_password_hashes].insert(id: id, password_hash: password_hash)
    rescue Sequel::UniqueConstraintViolation
      abort "An account for '#{email}' already exists."
    end

    puts "Admin account '#{email}' created."
  end

  desc "Reset the TOTP lockout for an admin (prompts for email)"
  task :reset_totp_lockout do
    require 'core/load'
    require 'core/bootstrap'

    print 'Admin email: '
    email = STDIN.gets.to_s.chomp
    abort 'Email cannot be blank.' if email.empty?

    id = DB[:accounts].where(email: email).get(:id)
    abort "No admin account found for '#{email}'." if id.nil?

    otp_key = DB[:account_otp_keys].where(id: id)
    abort "'#{email}' has no TOTP key configured." if otp_key.empty?

    # last_use must hold a local timestamp: SQLite's CURRENT_TIMESTAMP (the
    # column default) stores UTC and reads back hours in the future on a
    # non-UTC machine, which makes Rodauth's replay protection reject every
    # code. Write a consistent local value, backdated one interval so the
    # code showing right now works immediately after unlocking.
    otp_key.update(num_failures: 0, last_use: Time.now - 60)

    puts "TOTP lockout reset for '#{email}'. Log in again using a fresh code."
  end

  desc "Remove all second-factor methods for an admin (prompts for email)"
  task :disable_totp do
    require 'core/load'
    require 'core/bootstrap'

    print 'Admin email: '
    email = STDIN.gets.to_s.chomp
    abort 'Email cannot be blank.' if email.empty?

    id = DB[:accounts].where(email: email).get(:id)
    abort "No admin account found for '#{email}'." if id.nil?

    # Mirrors Rodauth's two_factor_remove: every second-factor method goes,
    # restoring password-only login.
    removed_keys = DB[:account_otp_keys].where(id: id).delete
    removed_codes = DB[:account_recovery_codes].where(id: id).delete

    if removed_keys.zero? && removed_codes.zero?
      puts "'#{email}' has no second-factor methods configured (nothing removed)."
    else
      puts "Second-factor methods removed for '#{email}' " \
           "(#{removed_keys} TOTP key(s), #{removed_codes} recovery code(s)). " \
           'Password-only login is restored.'
    end
  end

  desc "Generate and store web.admin.hmac_secret in config/rubyca.yml"
  task :generate_hmac_secret do
    require 'core/load'
    require 'securerandom'

    unless $config.dig('web', 'admin', 'hmac_secret').to_s.empty?
      abort 'web.admin.hmac_secret is already set in config/rubyca.yml. Remove it first if you want to generate a new one.'
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
