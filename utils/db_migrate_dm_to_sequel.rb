require 'sequel'
require 'sqlite3'
require 'logger'

#Sequel.connect('sqlite://db/rubyca.db')
DB = Sequel.connect(adapter: :sqlite, database: "db/rubyca.db", logger: Logger.new('log/migration-db.log'))
DBO = Sequel.connect(adapter: :sqlite, database: "RubyCa.db", logger: Logger.new('log/migration-dbo.log'))

DB[:certificate_schemas].multi_insert(DBO[:ruby_ca_core_models_certificate_schemas].all)
DB[:certificates].multi_insert(DBO[:ruby_ca_core_models_certificates].all)
DB[:configs].multi_insert(DBO[:ruby_ca_core_models_configs].all)
DB[:csrs].multi_insert(DBO[:ruby_ca_core_models_csrs].all)
DB[:revokeds].multi_insert(DBO[:ruby_ca_core_models_revokeds].all)
DBO[:ruby_ca_core_models_crls].all.each do |r|
  DB[:crls].insert(id: r[:id], crl: r[:crl], certificate_id: r[:id])
end

