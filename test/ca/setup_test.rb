require "minitest/autorun"
require "openssl"

class OpenSslInteractionTest < Minitest::Test
  def test_export_with_passphrase_callback
    # 1. Create the crypto components
    key = OpenSSL::PKey::RSA.new(2048)
    cipher = OpenSSL::Cipher::AES256.new(:CFB)

    # 2. Track how many times OpenSSL asks for the password
    prompt_count = 0
    simulated_password = "Secret123"

    # 3. Pass a callback block to export
    encrypted_pem = key.export(cipher) do
      prompt_count += 1
      simulated_password # This string is fed directly to OpenSSL
      #puts prompt_count
    end
    #puts encrypted_pem
    

    # 4. Verify the results
    dec_key = OpenSSL::PKey::RSA.new(encrypted_pem, simulated_password)
    assert_match(/-----BEGIN RSA PRIVATE KEY-----/, encrypted_pem)
    assert_equal(key.to_pem, dec_key.to_pem)
    
    # OpenSSL calls the block once for the password, and once for confirmation
    assert_equal 2, prompt_count 
  end
end
