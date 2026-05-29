require_relative 'task_header'

require 'sequel'
require 'sqlite3'
require 'logger'
require 'dotenv/load'
require 'fileutils'

# Based on https://gist.github.com/kalmbach/4471560

namespace :db do
  Sequel.extension :migration

  desc "Generates a migration file with a timestamp and name"
  task :generate_migration, :name do |_, args|
    abort "Usage: rake db:generate_migration[migration_name]" unless args[:name]
    
    # Generate timestamped file name
    file_name = "#{Time.now.strftime('%Y%m%d%H%M%S')}_#{args[:name]}.rb"
    file_path = File.join("#{$root_dir}/db/migrations", file_name)
    
    # Create directory and file
    FileUtils.mkdir_p("#{$root_dir}/db/migrations") unless Dir.exist?("#{$root_dir}/db/migrations")
    
    # Template to Sequel para migrations
    migration_template = <<~MIGRATION
      Sequel.migration do
        change do
          # Write your migration code here.
        end
      end
    MIGRATION
    File.write(file_path, migration_template)
    puts "Created migration: #{file_path}"
  end
  
  desc "Prints current schema version"
  task :version do    
    version = if DB.tables.include?(:schema_info)
      DB[:schema_info].first[:version]
    end || 0

    puts "Schema Version: #{version}"
  end

  desc "Perform migration up to latest migration available"
  task :migrate do
    unless Dir.exist?("#{$root_dir}/log")
      FileUtils.mkdir_p("#{$root_dir}/log")
    end

    DB = Sequel.connect(adapter: :sqlite, database: "#{$root_dir}/db/rubyca-#{ENV['APP_ENV']}.db", logger: Logger.new("log/db-migration-#{ENV['APP_ENV']}.log"))
    Sequel::Migrator.run(DB, "#{$root_dir}/db/migrations")
    Rake::Task['db:version'].execute
  end
    
  desc "Perform rollback to specified target or full rollback as default"
  task :rollback, :target do |t, args|
    args.with_defaults(:target => 0)

    Sequel::Migrator.run(DB, "#{$root_dir}/db/migrations", :target => args[:target].to_i)
    Rake::Task['db:version'].execute
  end

  desc "Perform migration reset (full rollback and migration)"
  task :reset do
    Sequel::Migrator.run(DB, "#{$root_dir}/db/migrations", :target => 0)
    Sequel::Migrator.run(DB, "#{$root_dir}/db/migrations")
    Rake::Task['db:version'].execute
  end

  desc "Perform database migration from DataMapper to Sequel"
  task :migrate_dm_to_sequel do
    DB = Sequel.connect(adapter: :sqlite, database: "#{$root_dir}/db/rubyca-#{ENV['APP_ENV']}.db", logger: Logger.new("log/db-migration-#{ENV['APP_ENV']}.log"))
    puts "Connect legacy DM database #{$root_dir}/RubyCA.db"
    DBO = Sequel.connect(adapter: :sqlite, database: "#{$root_dir}/RubyCA.db", logger: Logger.new("log/migration-db-legacy-dm-#{ENV['APP_ENV']}.log"))
    DB[:certificate_schemas].multi_insert(DBO[:ruby_ca_core_models_certificate_schemas].all)
    DB[:certificates].multi_insert(DBO[:ruby_ca_core_models_certificates].all)
    DB[:configs].multi_insert(DBO[:ruby_ca_core_models_configs].all)
    DB[:csrs].multi_insert(DBO[:ruby_ca_core_models_csrs].all)
    DB[:revokeds].multi_insert(DBO[:ruby_ca_core_models_revokeds].all)
    puts "CRLs migration is handled separately to generate root crl."
    puts "Please run 'rake db:migrate_dm_crls_to_sequel' to perform CRLs migration"
  end

  desc "Perform database migration for CRLs from DataMapper to Sequel"
  task :migrate_dm_crls_to_sequel do
    require_relative 'task_header'
    print "#{$root_dir}\n"

    require 'io/console'
    require 'core/load'
    require 'core/bootstrap'
    require 'core/ca/setup'

    puts "Please type key password to #{$root_dir}/private/root_ca.pem"
    puts "Root password is required to generate new CRL with signed by root CA from legacy DM database."

    enc_key = File.read("#{$root_dir}/private/root_ca.pem")
    key_pass = STDIN.noecho(&:gets).chomp
    root_key = OpenSSL::PKey::RSA.new enc_key, key_pass
    root_rec = RubyCA::Core::Models::Certificate.get_by_cn($config['ca']['root']['cn'])
    root_cert  = OpenSSL::X509::Certificate.new root_rec.crt
    create_crl(root_rec.id, root_key, root_cert, 3650)

    puts "Connect legacy DM database #{$root_dir}/RubyCA.db"
    DBO = Sequel.connect(adapter: :sqlite, database: "#{$root_dir}/RubyCA.db", logger: Logger.new("log/migration-db-legacy-dm-#{ENV['APP_ENV']}.log"))

    intermediate_rec = RubyCA::Core::Models::Certificate.get_by_cn($config['ca']['intermediate']['cn'])
    intermediate_legacy_crl = DBO[:ruby_ca_core_models_crls].order(:id).last
    if intermediate_legacy_crl
      puts "Migrating intermediate CRL"
      DB[:crls].insert(data: intermediate_legacy_crl[:crl], certificate_id: intermediate_rec.id)
    end
  end
end
