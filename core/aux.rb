if __FILE__ == $0 then abort 'This file forms part of RubyCA and is not designed to be called directly. Please run ./RubyCA instead.' end

def get_crl_dist_uri(crl_id=2)
  # CRL distribuition URI.
  crl_dist_config = $config['ca']['crl']['dist']
  crldist=nil  
  unless RubyCA::Core::Models::Crl.find(id: crl_id).nil? || crl_dist_config.nil? || crl_dist_config['uri_prefix'].nil? || crl_dist_config['uri_prefix'].empty? || crl_dist_config['uri_prefix'] ===''
    crldist = crl_dist_config['uri_prefix'].map{|uri| "URI:#{uri}/ca-#{crl_id}.crl"}.join(',')
  end
  return crldist
end

def random_password(length=12)
  chars = ('0'..'9').to_a + ('A'..'Z').to_a + ('a'..'z').to_a + ('#'..'&').to_a + (':'..'?').to_a
  p=''
  (0..length).each do
    p+=chars[rand(chars.size)]
  end
  return p
end

def legacy_pkcs12(password=nil, name=nil, pkey=nil, certificate=nil, *root_ca_certs)
  tf_pem = Tempfile.new 'tf_pem'
  tf_pem.write certificate

  root_ca_certs.each do |arg|
    if arg.kind_of? Array
      arg.each { |cacert| tf_pem.write cacert}
    else
      cacert = arg
      tf_pem.write cacert
    end
  end
  tf_pem.write pkey
  tf_pem.rewind
  tf_pem.read
  tf_pem.close
  
  tf_p12 = Tempfile.new 'tf_p12'
  tf_p12.close

  # OpenSSL::PKCS12.create(params[:passphrase][:certificate], params[:cn], deckey, cert, [root_ca, root_int_ca], 'PBE-SHA1-3DES', 'PBE-SHA1-3DES')
  # I cannot generate a pkcs12 with MAC algorithm SHA1 using gem openssl.

  pid = spawn("openssl pkcs12 -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 -in #{tf_pem.path} -export -out #{tf_p12.path} -passin pass:#{password} -passout pass:#{password} -name #{name}")
  Process.wait pid
  p12 = OpenSSL::PKCS12.new tf_p12.open, password
  
  tf_p12.close
  tf_p12.unlink
  tf_pem.unlink
  return p12
end