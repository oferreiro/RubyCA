if __FILE__ == $0 then 
  abort 'This file forms part of RubyCA and is not designed to be called directly. Please run ./RubyCA instead.' 
end

require "etc"
  
=begin
def get_crl_dist_uri_old
  # CRL distribuition URI. 
  # if URI is blank or null use auto generation URI based on config.
  if $config['ca']['crl']['dist'].nil? || $config['ca']['crl']['dist']['uri'].nil? || $config['ca']['crl']['dist']['uri'] ===''
    #crldist = "URI:http://#{$config['web']['domain']}#{(':' + $config['web']['port'].to_s) unless $config['web']['port'] == 80}/ca.crl"  
  else
    crldist = $config['ca']['crl']['dist']['uri'].map{|uri| "URI:#{uri}"}.join(',')
  end
  return crldist
end
=end

def gen_self_signed_root(cipher)
  # Generate self signed root
  
  # Create root key
  root_key = OpenSSL::PKey::RSA.new 2048
  puts ''
  puts 'Enter a pass phrase for the root CA key. This is not stored by RubyCA.'
  open $root_dir + "/private/root_ca.pem", 'w', 0400 do |io|
    io.write root_key.export(cipher)
  end
  # Create root certificate
  root_name = OpenSSL::X509::Name.parse "/C=#{$config['ca']['root']['country']}/ST=#{$config['ca']['root']['state']}/L=#{$config['ca']['root']['locality']}/O=#{$config['ca']['root']['organisation']}/CN=#{$config['ca']['root']['cn']}"
  root_crt = OpenSSL::X509::Certificate.new
  root_crt.serial = 0x10000000000000000000000000000000 + rand(0x01000000000000000000000000000000)
  RubyCA::Core::Models::Config.create( name: 'last_serial', value: root_crt.serial.to_s )
  root_crt.version = 2
  root_crt.not_before = Time.utc(Time.now.year, Time.now.month, Time.now.day, 00, 00, 0)
  root_crt.not_after = root_crt.not_before  + ($config['ca']['root']['years'] * 365 * 24 * 60 * 60 - 1) + (($config['ca']['root']['years'] / 4).to_int * 24 * 60 * 60)
  root_crt.public_key = root_key.public_key
  root_crt.subject = root_name
  root_crt.issuer = root_name
  root_ef = OpenSSL::X509::ExtensionFactory.new
  root_ef.subject_certificate = root_crt
  root_ef.issuer_certificate = root_crt
  root_crt.add_extension root_ef.create_extension 'subjectKeyIdentifier', 'hash'
  root_crt.add_extension root_ef.create_extension 'basicConstraints', 'CA:TRUE', true
  root_crt.add_extension root_ef.create_extension 'keyUsage', 'cRLSign,keyCertSign', true
  
  root_crt.sign root_key, OpenSSL::Digest::SHA512.new
  @root_crt = RubyCA::Core::Models::Certificate.create( cn: "#{$config['ca']['root']['cn']}" )
  @root_crt.crt = root_crt.to_pem
  @root_crt.save
  create_crl(root_key, root_crt, @root_crt.id, 3650)
  
  return root_key,root_crt
end

def gen_intermediate(root_key, root_crt, cipher)
  # Generate intermediate certificate and key
  intermediate_key = OpenSSL::PKey::RSA.new 2048
  puts ''
  puts 'Enter a pass phrase for the intermediate CA key.'
  @intermediate_crt = RubyCA::Core::Models::Certificate.create( cn: "#{$config['ca']['intermediate']['cn']}" )
  @intermediate_crt.pkey = intermediate_key.export(cipher)
  
  # Generate intermediate csr
  intermediate_csr = OpenSSL::X509::Request.new
  intermediate_csr.version = 2
  intermediate_csr.subject = OpenSSL::X509::Name.parse "/C=#{$config['ca']['intermediate']['country']}/ST=#{$config['ca']['intermediate']['state']}/L=#{$config['ca']['intermediate']['locality']}/O=#{$config['ca']['intermediate']['organisation']}/CN=#{$config['ca']['intermediate']['cn']}"
  intermediate_csr.public_key = intermediate_key.public_key
  intermediate_csr.sign intermediate_key, OpenSSL::Digest::SHA512.new
  
  # Sign intermediate csr with root certficate
  intermediate_crt = OpenSSL::X509::Certificate.new
  @serial = RubyCA::Core::Models::Config.get('last_serial')
  intermediate_crt.serial = @serial.value.to_i + 1
  @serial.value = intermediate_crt.serial.to_s
  @serial.save
  intermediate_crt.version = 2
  intermediate_crt.not_before = Time.utc(Time.now.year, Time.now.month, Time.now.day, 00, 00, 0)
  intermediate_crt.not_after = intermediate_crt.not_before  + ($config['ca']['intermediate']['years'] * 365 * 24 * 60 * 60 - 1) + (($config['ca']['intermediate']['years'] / 4).to_int * 24 * 60 * 60)
  intermediate_crt.subject = intermediate_csr.subject
  intermediate_crt.public_key = intermediate_csr.public_key
  intermediate_crt.issuer = root_crt.subject
  intermediate_ef = OpenSSL::X509::ExtensionFactory.new
  intermediate_ef.subject_certificate = intermediate_crt
  intermediate_ef.issuer_certificate = root_crt
  intermediate_crt.add_extension intermediate_ef.create_extension 'subjectKeyIdentifier', 'hash'
  intermediate_crt.add_extension intermediate_ef.create_extension 'basicConstraints', 'CA:TRUE', true
  intermediate_crt.add_extension intermediate_ef.create_extension 'keyUsage', 'cRLSign,keyCertSign', true 
  intermediate_crt.add_extension intermediate_ef.create_extension 'crlDistributionPoints', "#{get_crl_dist_uri}" unless get_crl_dist_uri.nil?

  intermediate_crt.sign root_key, OpenSSL::Digest::SHA512.new
  @intermediate_crt.crt = intermediate_crt.to_pem
  @intermediate_crt.save
  create_crl(@intermediate_crt.id, intermediate_key, intermediate_crt, 30)
  return intermediate_key, intermediate_crt
end

def create_crl(cert_id, key, cert, valid_days)
  # Create CRL
  crl = OpenSSL::X509::CRL.new
  crl.version = 1
  crl.issuer = cert.subject
  crl.last_update = Time.now
  crl.next_update = Time.now + valid_days * 24 * 60 * 60
  crl.sign key, OpenSSL::Digest::SHA512.new
  @crl = RubyCA::Core::Models::CRL.create(id: cert_id, crl: crl.to_pem)
end

def renew_crl(crl_id, key, cert, valid_days)
  crl_rec = RubyCA::Core::Models::CRL.get(crl_id)
  crl = OpenSSL::X509::CRL.new crl_rec.crl
  
  crl.last_update = Time.now
  crl.next_update = Time.now + valid_days * 24 * 60 * 60
  crl.sign key, OpenSSL::Digest::SHA512.new

  crl_rec.crl = crl.to_pem
  crl_rec.save
end

def renew_root_crl(key_pass)
  
  enc_key = File.read($root_dir + "/private/root_ca.pem")
  root_key = OpenSSL::PKey::RSA.new enc_key, key_pass
  root_rec = RubyCA::Core::Models::Certificate.get_by_cn($config['ca']['root']['cn'])
  root_cert  = OpenSSL::X509::Certificate.new root_rec.crt
  renew_crl(root_rec.id, root_key, root_cert, 3650)
  
end

# Check if the root certificate exists, if not, continue with generation
unless RubyCA::Core::Models::Config.get('first_run_complete')
  unsafe_mode = false
  ARGV.each do |p|
    if p === "-u" || p === "--unsafe"
      unsafe_mode = true
      puts ''
      puts '******************************************************************'
      puts '* You are running setup in unsafe mode.                          *'
      puts '* Be careful with root private key. It is a very sensitive file. *'
      puts '* I presume you know what are you doing.                         *'
      puts '******************************************************************'
      puts ''
    end
  end
  
  unless Process.euid == 0 || unsafe_mode
    puts ''
    puts '*************************************************************************************'    
    puts '* Error:                                                                            *'
    puts '* First RubyCA run requires root privilege to generate admin CA certificates.       *' 
    puts '* After this, the root privilege is not necessary if server port greater than 1024. *' 
    puts '* Please run RubyCA with sudo.                                                      *'
    puts '* sudo ./RubyCA                                                                     *'
    puts '* If you unable to run sudo, use --unsafe param with caution.                       *'
    puts '* ./RubyCA --unsafe                                                                 *'
    puts '*************************************************************************************'
    puts ''
    
    abort
  end
  
  puts ''
  puts 'This appears to be RubyCA\'s first run. RubyCA will be generate the root and intermediate CA certificates.'

# Generate certificates  
  puts ''
  puts 'Generating root and intermediate certificates...'
  
  # Check folders and permissions
  if Dir.exist? $root_dir + '/private/' then FileUtils.rm_r $root_dir + '/private/' end
  Dir.mkdir $root_dir + '/private', 0755
  
  # Common variables
  cipher = OpenSSL::Cipher.new 'AES-256-CBC'
  
  root_key, root_crt = gen_self_signed_root(cipher)
  intermediate_key, intermediate_crt = gen_intermediate(root_key, root_crt, cipher)  
  
  # Finish up
  puts ''
  puts 'Sucessfully generated root and imtermediate certificates.\n'

  puts '******************************************************************'
  puts '* Warning: The root private key has been encrypted and saved to  *'
  puts '* ./private/root_ca.pem                                          *'
  puts '* Consider moving it to a secure device.                         *'
  puts '******************************************************************'
  
  RubyCA::Core::Models::Config.create( name: 'first_run_complete', value: true )
  unless ($config['privileges'].nil?)
    uid = nil
    gid = nil
    
    unless ($config['privileges']['user'].nil? || $config['privileges']['user'] ==='')
      begin
        info = Etc.getpwnam($config['privileges']['user'])
      rescue
        puts "\nUser #{$config['privileges']['user']} does not exists."
      else
        uid = info.uid
      end
    end
    
    unless ($config['privileges']['group'].nil? || $config['privileges']['group'] ==='')
      begin
        ginfo = Etc.getgrnam($config['privileges']['group'])
      rescue
        puts "\nGroup #{$config['privileges']['group']} does not exists."
      else
        gid = ginfo.gid
      end
    end
    if (!uid.nil? || !gid.nil?)
      puts "#{$root_dir}/RubyCA.db"
      File.chown(uid,gid,"#{$root_dir}/RubyCA.db")
    end
  end
end