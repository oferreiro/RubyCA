source 'https://rubygems.org'

gem 'sinatra', '~> 4.2', '>= 4.2.1'
gem 'sinatra-flash'

gem 'rackup', '~> 2.3', '>= 2.3.1'
gem 'haml', '~> 6.4'
gem 'sequel', '~> 5.104'
gem 'sqlite3', '~> 2.9', '>= 2.9.4'
gem 'ipaddress', '~> 0.8.3'
gem 'rubyzip', '~> 3.3'

# Admin authentication (Rodauth as Rack middleware in front of Sinatra)
gem 'rodauth'   # pulls in roda; Sequel already present
gem 'bcrypt'    # password hashing
gem 'rotp'      # TOTP (required by rodauth's otp feature)
gem 'rqrcode'   # QR code for TOTP setup

# puma is default server now
gem 'puma', '~> 8.0', '>= 8.0.1'

gem 'dotenv', '~> 3.2'

group :development do
  gem 'sinatra-contrib', '~> 4.2', '>= 4.2.1'
end

group :test do
  gem 'rake', '~> 13.4', '>= 13.4.2'
  gem 'minitest', '~> 6.0', '>= 6.0.6'
  gem 'rack-test', '~> 2.1'
end

group :development, :test do
  gem 'irb'
end