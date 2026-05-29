if __FILE__ == $0 then abort 'This file forms part of RubyCA and is not designed to be called directly. Please run ./RubyCA instead.' end

require 'core/privileges'
require 'core/aux'
require 'sequel'
require 'sqlite3'

DB = Sequel.connect(adapter: :sqlite, database: "#{$root_dir}/db/rubyca-#{ENV['APP_ENV']}.db", logger: Logger.new("log/db-#{ENV['APP_ENV']}.log"))

require 'core/models/config'
require 'core/models/csr'
require 'core/models/certificate'
require 'core/models/certificate_schema'
require 'core/models/revoked'
require 'core/models/crl'
