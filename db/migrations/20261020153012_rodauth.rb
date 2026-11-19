Sequel.migration do
  up do
    create_table(:account_statuses) do
      primary_key :id
      String :name, :size=>50, :null=>false
    end

    from(:account_statuses).insert(:id=>1, :name=>'Unverified')
    from(:account_statuses).insert(:id=>2, :name=>'Verified')
    from(:account_statuses).insert(:id=>3, :name=>'Closed')

    create_table(:accounts) do
      primary_key :id
      String :email, :null=>false
      foreign_key :status_id, :account_statuses, :type=>Integer, :null=>false, :default=>1
      index :email, :unique=>true
    end

    create_table(:account_password_hashes) do
      foreign_key :id, :accounts, :primary_key=>true
      String :password_hash, :null=>false
    end

    create_table(:account_otp_keys) do
      foreign_key :id, :accounts, :primary_key=>true
      String :key, :null=>false
      Integer :num_failures, :null=>false, :default=>0
      # last_use drives Rodauth's OTP replay protection (a code cannot be
      # reused within one interval). Nullable, but always written as a
      # local timestamp by core/web/auth.rb: the UTC CURRENT_TIMESTAMP
      # default reads back in the future and rejects every code.
      DateTime :last_use, :null=>true, :default=>Sequel::CURRENT_TIMESTAMP
    end

    create_table(:account_recovery_codes) do
      foreign_key :id, :accounts, :null=>false
      String :code, :null=>false
      primary_key [:id, :code]
      index :id
    end
  end

  down do
    drop_table(:account_recovery_codes)
    drop_table(:account_otp_keys)
    drop_table(:account_password_hashes)
    drop_table(:accounts)
    drop_table(:account_statuses)
  end
end
