require_relative '../test_helper'
require 'tmpdir'
require 'stringio'
require 'fileutils'
require 'core/ca/setup'

class FirstRunSetupTest < Minitest::Test
  def setup
    DB[:crls].delete
    DB[:certificates].delete
    DB[:configs].delete

    @orig_root_dir = $root_dir
    @orig_stdin = $stdin
    @orig_privileges = $config['privileges']
    @temp_root = Dir.mktmpdir('rubyca-first-run-test')

    $root_dir = @temp_root
    $config['privileges'] = nil
  end

  def teardown
    $stdin = @orig_stdin
    $root_dir = @orig_root_dir
    $config['privileges'] = @orig_privileges

    FileUtils.rm_rf(@temp_root) if @temp_root && Dir.exist?(@temp_root)

    DB[:crls].delete
    DB[:certificates].delete
    DB[:configs].delete
  end

  def test_first_run_setup_reads_passwords_from_stdin_when_unsafe
    root_password = 'root-pass-123'
    intermediate_password = 'inter-pass-456'
    password_input = StringIO.new([
      root_password,
      root_password,
      intermediate_password,
      intermediate_password
    ].join("\n") + "\n")

    OpenSSL::PKey::RSA.singleton_class.class_eval do
      alias_method :__orig_new, :new
      define_method(:new) do |*args, &block|
        key = __orig_new(*args, &block)
        key.define_singleton_method(:export) do |cipher, pass=nil, &blk|
          if pass.nil?
            super(cipher) { password_input.gets&.chomp }
          else
            super(cipher, pass, &blk)
          end
        end
        key
      end
    end

    first_run_setup(true)
  ensure
    OpenSSL::PKey::RSA.singleton_class.class_eval do
      alias_method :new, :__orig_new
      remove_method :__orig_new
    end

    root_pem = File.read(File.join($root_dir, 'private', 'root_ca.pem'))
    assert_match(/-----BEGIN RSA PRIVATE KEY-----/, root_pem)
    OpenSSL::PKey::RSA.new(root_pem, root_password)

    intermediate_record = RubyCA::Core::Models::Certificate.find(cn: $config['ca']['intermediate']['cn'])
    refute_nil intermediate_record

    intermediate_pem = intermediate_record.pkey
    assert_match(/-----BEGIN RSA PRIVATE KEY-----/, intermediate_pem)
    assert_match(/Proc-Type: 4,ENCRYPTED/, intermediate_pem)
    assert_match(/DEK-Info: AES-256-CBC/, intermediate_pem)

    first_run_flag = RubyCA::Core::Models::Config.find(name: 'first_run_complete')
    refute_nil first_run_flag
    assert_equal 'true', first_run_flag.value
  end
end
