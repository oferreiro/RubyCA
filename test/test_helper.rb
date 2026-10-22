require 'minitest/autorun'

$LOAD_PATH.unshift File.expand_path('../..', __FILE__)
ENV['APP_ENV'] = 'test' # Tells Sinatra it is in test mode

require 'sequel'
require 'dotenv'
Dotenv.overload('.env.test', '.env')

DB = Sequel.sqlite
Sequel::Model.db = DB
Sequel.extension :migration
Sequel::Migrator.run(DB, "db/migrations")

# DB.create_table(:certificates) do
#   primary_key :id
#   String :cn, size: 64, null: false
#   String :crt, text: true
#   String :pkey, text: true
#   index :cn, unique: true
# end

# DB.create_table(:crls) do
#   primary_key :id
#   String :data, text: true
#   foreign_key :certificate_id, :certificates, unique: true, null: false
# end

require 'core/header'
require 'core/load'
require 'core/bootstrap'

# require 'core/models/certificate'
# require 'core/models/crl'
