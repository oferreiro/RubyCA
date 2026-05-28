# Set our root dir
$:.unshift(File.join(File.expand_path(File.dirname(__FILE__)), '.'))
$root_dir = File.expand_path('..', __FILE__)

require 'core/load'
require 'core/bootstrap'
require 'core/web/server'
require 'core/web/flash'

configure :development do
	puts "development mode"
end
configure :production do
	puts "production mode"
	puts Gem.loaded_specs.keys
end
configure :test do
	puts "test mode"
end

run RubyCA::Core::Web::Server
