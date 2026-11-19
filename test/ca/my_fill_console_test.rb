require "minitest/autorun"
require "openssl"
require 'stringio'

class OpenSslInteractionTest < Minitest::Test
  def test_export_ssl_key
    # 1. Create the crypto components
    key = OpenSSL::PKey::RSA.new(2048)
    cipher = OpenSSL::Cipher::AES256.new(:CFB)
    simulated_password = "SecretPassword123"

    original_stdin = $stdin
    input=StringIO.new("#{simulated_password}\n#{simulated_password}\n")
    $stdin=input
    
    encrypted_pem = wrap_export(cipher, key)

    # 4. Run your assertions
    assert_match(/-----BEGIN RSA PRIVATE KEY-----/, encrypted_pem)
    
    # Decrypt to ensure the password applied properly
    dec_key = OpenSSL::PKey::RSA.new(encrypted_pem, simulated_password)
    assert_equal(key.to_pem, dec_key.to_pem)

    ensure
      #restore standard input
      $stdin = original_stdin
  end
  private
    def wrap_export(cipher, key)
      key.export(cipher)
    end
end
