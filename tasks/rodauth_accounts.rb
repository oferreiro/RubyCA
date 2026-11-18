# Admin account operations shared by the rodauth:* rake tasks.
#
# Requires core/load + core/bootstrap to have run (uses the DB constant).
# Every failure raises RodauthAccounts::Error with a user-facing message:
# single-purpose tasks turn it into `abort`, the interactive
# rodauth:manage_accounts menu prints it and returns to the menu.
require 'io/console'
require 'bcrypt'

module RodauthAccounts
  class Error < StandardError; end

  # status_id 2 = Verified (see the account_statuses table)
  VERIFIED_STATUS = 2

  module_function

  # --- prompts ------------------------------------------------------------

  # Reads one line from STDIN; nil on EOF.
  def ask(label)
    print label
    line = STDIN.gets
    line&.chomp
  end

  def ask_email(label = 'Admin email: ')
    email = ask(label).to_s.strip
    raise Error, 'Email cannot be blank.' if email.empty?
    email
  end

  # Hidden password prompt with confirmation.
  def ask_new_password(intro = 'Admin password (input is hidden):')
    puts intro
    print 'Password: '
    password = STDIN.noecho(&:gets).to_s.chomp
    puts ''
    print 'Confirm password: '
    confirm_password = STDIN.noecho(&:gets).to_s.chomp
    puts ''

    raise Error, 'Password cannot be blank.' if password.empty?
    raise Error, 'Password and confirm password do not match.' unless password == confirm_password
    password
  end

  # --- queries ------------------------------------------------------------

  def find_id!(email)
    id = DB[:accounts].where(email: email).get(:id)
    raise Error, "No admin account found for '#{email}'." if id.nil?
    id
  end

  # [{id:, email:, status:, totp:, otp_failures:, recovery_codes:}, ...]
  def list
    otp = DB[:account_otp_keys].to_hash(:id, :num_failures)
    codes = DB[:account_recovery_codes].group_and_count(:id).to_hash(:id, :count)
    statuses = DB[:account_statuses].to_hash(:id, :name)

    DB[:accounts].order(:email).map do |a|
      {
        id: a[:id],
        email: a[:email],
        status: statuses[a[:status_id]] || a[:status_id].to_s,
        totp: otp.key?(a[:id]),
        otp_failures: otp[a[:id]].to_i,
        recovery_codes: codes[a[:id]].to_i
      }
    end
  end

  # --- mutations ----------------------------------------------------------

  def create(email, password)
    DB.transaction do
      id = DB[:accounts].insert(email: email, status_id: VERIFIED_STATUS)
      DB[:account_password_hashes].insert(id: id, password_hash: BCrypt::Password.create(password))
      id
    end
  rescue Sequel::UniqueConstraintViolation
    raise Error, "An account for '#{email}' already exists."
  end

  def change_password(id, password)
    hash = BCrypt::Password.create(password)
    updated = DB[:account_password_hashes].where(id: id).update(password_hash: hash)
    DB[:account_password_hashes].insert(id: id, password_hash: hash) if updated.zero?
  end

  def change_email(id, new_email)
    DB[:accounts].where(id: id).update(email: new_email)
  rescue Sequel::UniqueConstraintViolation
    raise Error, "An account for '#{new_email}' already exists."
  end

  # Removes the account and every dependent row (FKs reference accounts.id).
  def delete(id)
    DB.transaction do
      DB[:account_recovery_codes].where(id: id).delete
      DB[:account_otp_keys].where(id: id).delete
      DB[:account_password_hashes].where(id: id).delete
      DB[:accounts].where(id: id).delete
    end
  end

  # Zeroes the TOTP failure counter, keeping TOTP enrolled.
  #
  # last_use must hold a local timestamp: SQLite's CURRENT_TIMESTAMP (the
  # column default) stores UTC and reads back hours in the future on a
  # non-UTC machine, which makes Rodauth's replay protection reject every
  # code. Write a consistent local value, backdated one interval so the
  # code showing right now works immediately after unlocking.
  def reset_totp_lockout(id, email)
    otp_key = DB[:account_otp_keys].where(id: id)
    raise Error, "'#{email}' has no TOTP key configured." if otp_key.empty?
    otp_key.update(num_failures: 0, last_use: Time.now - 60)
  end

  # Mirrors Rodauth's two_factor_remove: every second-factor method goes,
  # restoring password-only login. Returns [removed_keys, removed_codes].
  def disable_two_factor(id)
    DB.transaction do
      [DB[:account_otp_keys].where(id: id).delete,
       DB[:account_recovery_codes].where(id: id).delete]
    end
  end

  def disable_two_factor_message(email, removed_keys, removed_codes)
    if removed_keys.zero? && removed_codes.zero?
      "'#{email}' has no second-factor methods configured (nothing removed)."
    else
      "Second-factor methods removed for '#{email}' " \
        "(#{removed_keys} TOTP key(s), #{removed_codes} recovery code(s)). " \
        'Password-only login is restored.'
    end
  end
end
