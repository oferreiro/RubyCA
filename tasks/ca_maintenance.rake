require_relative 'task_header'

require 'io/console'

namespace :ca do  

  # Syntax: task :name, [:args] => [:prerequisites]
  task :test_arg, [:unsafe] do |t, args|
    if args[:unsafe] == "unsafe"
      puts "You have entered unsafe argument!"
    else
      puts "This is a safe argument."
    end
  end

  desc "Perform CA setup"
  task :setup, [:unsafe] do |t, args|
    require 'core/load'
    require 'core/bootstrap'
    require 'core/ca/setup'
    unsafe = args[:unsafe] == "unsafe"
    first_run_setup(unsafe)
  end

  desc "Perform renew root CA certificate and CRL"
  task :renew_root_certificate do
    require 'core/load'
    require 'core/bootstrap'
    require 'core/ca/setup'
    puts "Please type key password to #{$root_dir}/private/root_ca.pem"    
    key_pass = STDIN.noecho(&:gets).chomp
    renew_root_certificate(key_pass)
    puts "Root CA certificate and CRL renewed successfully."
  end

  desc "Perform renew intermediate CA certificate and CRL"
  task :renew_intermediate_certificate do
    require 'core/load'
    require 'core/bootstrap'
    require 'core/ca/setup'
    puts "Please type key password to #{$root_dir}/private/root_ca.pem"
    root_key_pass = STDIN.noecho(&:gets).chomp

    puts "Please type key password to Intermediate CA key"
    intermediate_key_pass = STDIN.noecho(&:gets).chomp

    renew_intermediate_certificate(root_key_pass, intermediate_key_pass)
    puts "Intermediate CA certificate and CRL renewed successfully."
  end
end