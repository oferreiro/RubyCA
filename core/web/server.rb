if __FILE__ == $0 then abort 'This file forms part of RubyCA and is not designed to be called directly. Please run ./RubyCA instead.' end

module RubyCA
  module Core
    module Web
      class Server < Sinatra::Base
        configure :development do
          register Sinatra::Reloader
        end
        
        use Rack::MethodOverride
        use Rack::Session::Pool
        register Sinatra::Flash
        set :bind, $config['web']['interface']
        set :port, $config['web']['port']
        set :haml, layout: :layout
        mime_type :pem, 'pem/pem'
        mime_type :ocsp, 'application/ocsp-response'
        mime_type :p12, 'application/x-pkcs12'
        mime_type :zip, 'application/zip'


        keyusages = {
          'digitalSignature'  => true,
          'dataEncipherment'  => true,
          'keyEncipherment'   => false,
          'keyAgreement'      => false,
          'nonRepudiation'    => false,
          'cRLSign'           => false
        }
        
        extendedkeyusages = { 
          'clientAuth'        => true,
          'serverAuth'        => false,
          'emailProtection'   => false,
          'ipsecEndSystem'    => false,
          'ipsecTunnel'       => false,
          'ipsecUser'         => false,
          #'1.3.6.1.5.5.8.2.2' => false #iKEIntermediate
        }

        key_usage_map = {
          'Digital Signature' => 'digitalSignature',
          'Non Repudiation'   => 'nonRepudiation',
          'Key Encipherment'  => 'keyEncipherment',
          'Data Encipherment' => 'dataEncipherment',
          'Key Agreement'     => 'keyAgreement',
          'Certificate Sign'  => 'cRLSign',
          'CRL Sign'          => 'cRLSign'
        }

        extended_key_usage_map = {
          'TLS Web Client Authentication' => 'clientAuth',
          'TLS Web Server Authentication' => 'serverAuth',
          'E-mail Protection'             => 'emailProtection',
          'IPSec End System'              => 'ipsecEndSystem',
          'IPSec Tunnel'                  => 'ipsecTunnel',
          'IPSec User'                    => 'ipsecUser'
        }
        
        helpers do
          def host_allowed?(addr)
            allowed = false
            ip_addr = IPAddress addr
            
            $config['web']['admin']['allowed_ips'].each do |allowed_ip|
              allow = IPAddress allowed_ip
              if (ip_addr.ipv4? && allow.ipv4?) || (ip_addr.ipv6? && allow.ipv6?)
                if allow.include? ip_addr
                  allowed = true
                  break
                end
              end
            end
            allowed
          end
          
          def protected!
            authcfg = $config['web']['admin']['auth']
            @user = authcfg['username'] unless authcfg.nil? || authcfg.empty?
            @pass = authcfg['password'] unless authcfg.nil? || authcfg.empty?
            permit_auth = authcfg['enable'] && !(authcfg.nil? || authcfg.empty? || @user.nil? || @user.empty? || @pass.nil? || @pass.empty?)
            
            unless authorized?
              if permit_auth
                response['WWW-Authenticate'] = %(Basic realm="Restricted Area")
              end
              throw(:halt, [401, "401 - Not authorized!\n"])
            end
          end

          def authorized?
            auth = Rack::Auth::Basic::Request.new(request.env)
            auth.provided? && auth.basic? && auth.credentials && @user == Digest::SHA2.hexdigest(auth.credentials[0]) && @pass == Digest::SHA2.hexdigest(auth.credentials[1])
          end
          
          def get_crl_info(id)
            crl_rec = RubyCA::Core::Models::Crl.find(id: id)
            crl = OpenSSL::X509::CRL.new crl_rec.data
            issuer = {}
            crl.issuer().to_s.split("/").each do |x|
              if x!=""
                k,v = x.split("=")
                issuer[k] = v
              end
            end
            crl_info = {}
            crl_info[:id] = crl_rec.id
            crl_info[:issuer] = issuer
            crl_info[:last_update] = Time.parse(crl.last_update().to_s)
            crl_info[:next_update] = Time.parse(crl.next_update().to_s)
            crl_info[:to_expire] = false
            crl_info[:expired] = false
            
            if Time.now.utc > crl_info[:next_update]
              crl_info[:expired] = true
            end
            
            if Time.now.utc + (5*24*60*60) > crl_info[:next_update]
              crl_info[:to_expire] = true
            end
            crl_info
          end
        end
        
        before '/admin*' do
          remote_addr = request.env['HTTP_X_REAL_IP'] || request.env['HTTP_X_FORWARDED_FOR'] || request.ip
          unless host_allowed?(remote_addr)
            protected!
          end
        end
        
        get '/' do
          redirect '/admin'
        end
        
        # to kepp compatibility with old versions certificates
        get '/ca.crl' do
          crl = OpenSSL::X509::CRL.new RubyCA::Core::Models::Certificate.find(cn: $config['ca']['intermediate']['cn']).crl.data
          content_type :crl
          crl.to_der
        end
        
        get '/crl.pem' do
          crl = OpenSSL::X509::CRL.new RubyCA::Core::Models::Certificate.find(cn: $config['ca']['intermediate']['cn']).crl.data
          content_type :crl
          crl.to_pem
        end

        get '/ca-:id.crl' do
          crl_rec = RubyCA::Core::Models::Crl.find(id: params[:id])
          unless crl_rec
            halt 404
          end
          crl = OpenSSL::X509::CRL.new crl_rec.data
          content_type :crl
          crl.to_der
        end

        get '/ca-:id.pem' do
          crl_rec = RubyCA::Core::Models::Crl.find(id: params[:id])
          unless crl_rec
            halt 404
          end
          crl = OpenSSL::X509::CRL.new crl_rec.data
          content_type :crl
          crl.to_pem
        end

        get '/root-ca.zip' do
          root_rec = RubyCA::Core::Models::Certificate.find(cn: $config['ca']['root']['cn'])
          intermediate_rec = RubyCA::Core::Models::Certificate.find(cn: $config['ca']['intermediate']['cn'])
          root_crt = OpenSSL::X509::Certificate.new root_rec.crt
          intermediate_crt = OpenSSL::X509::Certificate.new intermediate_rec.crt
          root_fname = root_rec.cn.downcase.gsub(/\s+/, '_')
          intermediate_fname = intermediate_rec.cn.downcase.gsub(/\s+/, '_')
          
          zbuf = Zip::OutputStream.write_buffer do |out|
            out.put_next_entry("#{root_fname}.crt")
            out.write(root_crt.to_pem)
            
            out.put_next_entry("#{intermediate_fname}.crt")
            out.write(intermediate_crt.to_pem)
          end
          content_type :zip
          zbuf.string
        end
        
        get '/admin/?' do
          haml :admin
        end
        
        #
        # Config
        #
        get '/admin/configs/?' do
          redirect "/admin/config/0"
        end

        get '/admin/config/?' do
          if session[:config].nil? || session[:config][:tab_id].nil?
            @tab_id=0
          else
            if (0..2).include?(session[:config][:tab_id])
              @tab_id=session[:config][:tab_id]
            else
              @tab_id=0
            end
            session[:config][:tab_id] = nil
          end

          @authcfg = $config['web']['admin']['auth']
          @allowed_ips = $config['web']['admin']['allowed_ips']
          @my_ip = request.env['HTTP_X_REAL_IP'] || request.env['HTTP_X_FORWARDED_FOR'] || request.ip
          
          @vpn_defaults = {}
          config_vpn_defaults = RubyCA::Core::Models::Config.find(name: "vpn_defaults_server_address")
          @vpn_defaults['server_address'] = config_vpn_defaults.value unless config_vpn_defaults.nil?
          config_vpn_defaults = RubyCA::Core::Models::Config.find(name: "vpn_defaults_iface_name")
          @vpn_defaults['iface_name'] = config_vpn_defaults.value unless config_vpn_defaults.nil?
          
          haml :config
        end
        
        post '/admin/config' do
          unless params[:tab_id].nil?
            if (0..2).include?(params[:tab_id].to_i)
              tab_id= { tab_id: params[:tab_id].to_i }
              session[:config]=tab_id
            else
              unless session[:config].nil? && session[:config][:tab_id].nil?
                session[:config][:tab_id]=nil
              end
            end
          end

          if File.writable?(CFG_FILE)
            #Simple User and password auth
            if !params[:authcfg].nil? && params[:authcfg][:auth] == '1'
              $config['web']['admin']['auth'] ||={}
          
              username = params[:authcfg][:username]
              password = params[:authcfg][:password]
              confirm_password = params[:authcfg][:confirm_password]
              enable = params[:authcfg][:enable] == "1" ? true : false
              
              unless username.nil? || username.empty? || password.nil? || password.empty? || confirm_password.nil? || confirm_password.empty?
                if password == confirm_password
                  $config['web']['admin']['auth']['username'] = Digest::SHA2.hexdigest(username) 
                  $config['web']['admin']['auth']['password'] = Digest::SHA2.hexdigest(password)
                  $config['web']['admin']['auth']['enable'] = enable
          
                  File.open(CFG_FILE, 'w') {|f| YAML.dump($config, f) } #Store
                  $config = YAML.load(File.read(CFG_FILE)) # Reload
                  flash.next[:success] = "Admin authentication settings stored"
                else
                  flash.next[:danger] = "Password and confirm password does not match."
                end
              else
                flash.next[:danger] = "Username, Password and Confirm Password cannot be blank."
              end
            end
          
            #Allow IP Address
            if !params[:authcfg].nil? && params[:authcfg][:allow_ip] == '1'
              $config['web']['admin']['allowed_ips'] ||={}
              begin
                ip = IPAddress params[:authcfg][:ip]              
              rescue  
                flash.next[:danger] =  "Invalid network or ip address! <strong>(#{params[:authcfg][:ip]})</strong>"
              end
            
              unless ip.nil?          
                #unless $config['web']['admin']['allowed_ips'].include? params[:authcfg][:ip]
                unless host_allowed?(params[:authcfg][:ip])
                  if ip.network?
                    $config['web']['admin']['allowed_ips'].push("#{ip}/#{ip.prefix}")
                  else
                    $config['web']['admin']['allowed_ips'].push("#{ip}")
                  end
              
                  File.open(CFG_FILE, 'w') {|f| YAML.dump($config, f) } #Store
                  $config = YAML.load(File.read(CFG_FILE)) # Reload
                  flash.next[:success] = "<strong>#{params[:authcfg][:ip]}</strong> added to allowed ips."
                else
                  flash.next[:warning] = "<strong>#{params[:authcfg][:ip]}</strong> is already allowed ip address."
                end
              end
            end
          
            #Disallow IP Address
            if !params[:authcfg].nil? && params[:authcfg][:disallow_ips] == '1'
              $config['web']['admin']['allowed_ips'] ||={}
            
              params[:authcfg][:ips].each do |ip|
                $config['web']['admin']['allowed_ips'].delete("#{ip}")
              end
            
              File.open(CFG_FILE, 'w') {|f| YAML.dump($config, f) } #Store
              $config = YAML.load(File.read(CFG_FILE)) # Reload
              flash.next[:success] = "<strong>#{params[:authcfg][:ips]}</strong> deleted from allowed ips."
            end

            # Save vpn defaults settings
            msg = ''
            unless params[:vpn_defaults].nil?
              unless params[:vpn_defaults][:server_address].nil?
                config_vpn_defaults = RubyCA::Core::Models::Config.find(name: "vpn_defaults_server_address")
                if config_vpn_defaults.nil?
                  config_vpn_defaults = RubyCA::Core::Models::Config.create(name: "vpn_defaults_server_address", value: '')
                end
                config_vpn_defaults.value = params[:vpn_defaults][:server_address]
                config_vpn_defaults.save
                msg = "</br>server address: <strong>#{params[:vpn_defaults][:server_address]}</strong> Saved"
              end

              unless params[:vpn_defaults][:iface_name].nil?
                config_vpn_defaults = RubyCA::Core::Models::Config.find(name: "vpn_defaults_iface_name")
                if config_vpn_defaults.nil?
                  config_vpn_defaults = RubyCA::Core::Models::Config.create(name: "vpn_defaults_iface_name", value: '')
                end
                config_vpn_defaults.value = params[:vpn_defaults][:iface_name]
                config_vpn_defaults.save
                msg += "</br>interface name: <strong>#{params[:vpn_defaults][:iface_name]}</strong> Saved"
              end
              flash.next[:success] = "#{msg}"
            end
          else
            flash.next[:danger] = "<strong>#{CFG_FILE}</strong> is not writable. Fix it before set anything here."
          end                  
          redirect "/admin/config"
        end
        
        #
        # CRL
        #
        get '/admin/crl' do
          crl_recs = RubyCA::Core::Models::Crl.all
          @crl_infos = []
          crl_recs.each do |crl_rec|
            @crl_infos <<  get_crl_info(crl_rec.id)
          end
          @crl_dist = $config['ca']['crl']['dist']['uri_prefix']
          haml :crl
        end
        
        post '/admin/crl/config' do
          if File.writable?(CFG_FILE)
            
            #Add
            if params[:ca][:crl][:dist][:add_uri] == '1'
              $config['ca']['crl']['dist']['uri_prefix'] ||={}
              if (params[:ca][:crl][:dist][:uri_prefix]==="")
                flash.next[:danger] = "URI is empty."
              else
                unless $config['ca']['crl']['dist']['uri_prefix'].include? params[:ca][:crl][:dist][:uri_prefix]
                  $config['ca']['crl']['dist']['uri_prefix'].push(params[:ca][:crl][:dist][:uri_prefix])
                  File.open(CFG_FILE, 'w') {|f| YAML.dump($config, f) } #Store
                  $config = YAML.load(File.read(CFG_FILE)) # Reload
                  flash.next[:success] = "<strong>#{params[:ca][:crl][:dist][:uri_prefix]}</strong> added to crl distribution points list."
                else
                  flash.next[:warning] = "<strong>#{params[:ca][:crl][:dist][:uri_prefix]}</strong> is already in crl distribution points list."
                end
              end
            end
          
            #Remove
            if params[:ca][:crl][:dist][:rm_uri] == '1'
              unless (params[:ca][:crl][:dist][:uri_prefix].nil? || params[:ca][:crl][:dist][:uri_prefix]==="" )
                $config['ca']['crl']['dist']['uri_prefix'] ||={}
                params[:ca][:crl][:dist][:uri_prefix].each do |uri_prefix|
                  $config['ca']['crl']['dist']['uri_prefix'].delete("#{uri_prefix}")
                end
            
                File.open(CFG_FILE, 'w') {|f| YAML.dump($config, f) } #Store
                $config = YAML.load(File.read(CFG_FILE)) # Reload
                flash.next[:success] = "<strong>#{params[:ca][:crl][:dist][:uri_prefix]}</strong> deleted from crl distribution points list."
              else
                flash.next[:warning] = "Select the crl distribution point do you want delete."
              end
            end
            
          else
            flash.next[:danger] = "#{CFG_FILE} is not writable. Fix it before set anything here."
          end
          
          redirect '/admin/crl'
        end
                
        get '/admin/crl/:id/info' do
          crl_rec = RubyCA::Core::Models::Crl.find(id: params[:id])
          crl = OpenSSL::X509::CRL.new crl_rec.data
          content_type :txt
          crl.to_text 
        end
        
        get '/admin/crl/renew' do
          intermediate_rec = RubyCA::Core::Models::Certificate.find(cn: $config['ca']['intermediate']['cn'])
          @crl_info = get_crl_info(intermediate_rec.id)
          if @crl_info[:expired] || @crl_info[:to_expire]
            haml :crlrenew
          else            
            flash.next[:danger] = "CRL renewal is not necessary."
            redirect '/admin/crl'
          end
        end
        
        post '/admin/crl/renew' do
          intermediate_rec = RubyCA::Core::Models::Certificate.find(cn: $config['ca']['intermediate']['cn'])
          begin
            intermediate_key = OpenSSL::PKey::RSA.new intermediate_rec.pkey, params[:passphrase][:intermediate]
          rescue OpenSSL::PKey::RSAError
            session[:sign] = params
            flash.next[:danger] = "Incorrect intermediate CA key passphrase"
            redirect "/admin/crl/renew"
          end
          
          crl_info = get_crl_info(intermediate_rec.id)
          if !crl_info[:expired] && !crl_info[:to_expire]
            flash.next[:danger] = "CRL is not expired or to expire. Renewal is not necessary now."
            redirect '/admin/crl'
          end

          intermediate_crt = OpenSSL::X509::Certificate.new intermediate_rec.crt 
          crl = OpenSSL::X509::CRL.new intermediate_rec.crl.data
          
          crl.last_update = Time.now
          crl.next_update = Time.now + 30 * 24 * 60 * 60
          crl.sign intermediate_key, OpenSSL::Digest::SHA512.new
          intermediate_key = nil
          intermediate_rec.crl.data = crl.to_pem
          intermediate_rec.crl.save
          flash.next[:success] = "CRL successfully renewed"
          redirect '/admin/crl'
        end
        
        post '/admin/crl/renew.txt' do
          content_buffer = " "
          content_buffer += "---------------------------------------------------------------\n"
          content_buffer += " RubyCA - Renew CRL\n\n"
          content_buffer += "---------------------------------------------------------------\n"
          intermediate_rec = RubyCA::Core::Models::Certificate.find(cn: $config['ca']['intermediate']['cn'])
          validpw = false
          begin
            intermediate_key = OpenSSL::PKey::RSA.new intermediate_rec.pkey, params[:passphrase][:intermediate]
            validpw = true
          rescue OpenSSL::PKey::RSAError
            session[:sign] = params
            validpw = false
            content_buffer += "Incorrect intermediate CA key passphrase\n"
          end
          if validpw
            crl_info = get_crl_info(intermediate_rec.id)
            if !crl_info[:expired] && !crl_info[:to_expire]
              content_buffer += "CRL is not expired or to expire. Renewal is not necessary now.\n"
            else

              intermediate_crt = OpenSSL::X509::Certificate.new intermediate_rec.crt
              crl = OpenSSL::X509::CRL.new intermediate_rec.crl.data

              crl.last_update = Time.now
              crl.next_update = Time.now + 30 * 24 * 60 * 60
              crl.sign intermediate_key, OpenSSL::Digest::SHA512.new
              intermediate_key = nil
              intermediate_rec.crl.data = crl.to_pem
              intermediate_rec.crl.save
        
              content_buffer += "CRL successfully renewed.\n\n"

              crl = OpenSSL::X509::CRL.new intermediate_rec.crl.data
              content_buffer += crl.to_text
            end
          end
          content_type :txt
          content_buffer
        end
        
        #
        # Certificate Signing Requests
        #
        get '/admin/csrs/:cn/info' do
          csr_rec = RubyCA::Core::Models::Csr.find(cn: params[:cn])
          csr = OpenSSL::X509::Request.new csr_rec.csr
          content_type :txt
          csr.to_text 
        end
      
        get '/admin/csrs/?' do
          @csrs = RubyCA::Core::Models::Csr.all
          @cschemas = RubyCA::Core::Models::CertificateSchema.all
          @csr = session[:csr]
          haml :csrs
        end
        
        post '/admin/csrs/?' do
          session.delete(:csr)
          params[:csr].each do |k,v|
            if v.nil? || v.empty?
              session[:csr] = params[:csr]
              flash.next[:danger] = "All fields are required"
              redirect '/admin/csrs'
            end  
          end
          
          if params[:csr][:passphrase] != params[:csr][:confirm]
            session[:csr] = params[:csr]
            flash.next[:danger] = "Passphrase and confirm does not matches"
            redirect '/admin/csrs'
          end
          
          if RubyCA::Core::Models::Csr.find(cn: params[:csr][:cn])
            cn = params[:csr][:cn]
            session[:csr] = params[:csr]
            session[:csr][:cn] = nil
            flash.next[:danger] = "A certificate signing request already exists for <strong>'Common Name: #{cn}'</strong>"
            redirect '/admin/csrs'
          end
          
          csr_rec = RubyCA::Core::Models::Csr.create(
            cn: params[:csr][:cn],
            o: params[:csr][:o],
            l: params[:csr][:l],
            st: params[:csr][:st],
            c: params[:csr][:c] )
              
          cipher = OpenSSL::Cipher.new $default_cipher
          key = OpenSSL::PKey::RSA.new 2048
          csr_rec.pkey = key.export(cipher, params[:csr][:passphrase])
          csr = OpenSSL::X509::Request.new
          csr.version = 0
          csr.subject = OpenSSL::X509::Name.parse "/C=#{csr_rec.c}/ST=#{csr_rec.st}/L=#{csr_rec.l}/O=#{csr_rec.o}/CN=#{csr_rec.cn}"
          csr.public_key = key.public_key
          csr.sign key, OpenSSL::Digest::SHA512.new
          csr_rec.csr = csr.to_pem
          csr_rec.save
          flash.next[:success] = "Created certificate signing request for <strong>'#{csr_rec.cn}'</strong>"
          redirect '/admin/csrs'
        end
        
        get '/admin/csrs/cancel' do
          session.delete(:csr)
          redirect '/admin/csrs'
        end
        
        delete '/admin/csrs/:cn/?' do
          @csr = RubyCA::Core::Models::Csr.find(cn: params[:cn])
          @csr.destroy
          flash.next[:success] = "Deleted certificate signing request for '#{@csr.cn}'"
          redirect '/admin/csrs'
        end
        
        get '/admin/csrs/sign/cancel' do
          session.delete(:sign)
          redirect '/admin/csrs'
        end
        
        get '/admin/csrs/:cn/sign/?' do
          crt_rec = RubyCA::Core::Models::Certificate.find(cn: params[:cn])
          @csr_rec = RubyCA::Core::Models::Csr.find(cn: params[:cn])
          if crt_rec
            if @csr_rec && @csr_rec.pkey != crt_rec.pkey
              flash.next[:danger] = "A certificate with different key already exists for '#{params[:cn]}', revoke the old certificate before signing this request"
              redirect '/admin/csrs'
            end
          end
          
          csr = OpenSSL::X509::Request.new @csr_rec.csr
          @sign = session[:sign]
          
          ku = keyusages.clone
          eku = extendedkeyusages.clone

          # Load current certificate key usages and extended key usages if certificate already exists
          unless crt_rec.nil?
            #@san = { DNS: nil, IP: nil, URI: nil, email: nil, RID: nil }
            @san = {}
            SAN_PREFIX_MAP = {
              /^DNS:/               => :DNS,
              /^IP Address:/        => :IP,
              /^URI:/               => :URI,
              /^email:/             => :email,
              /^(Registered ID:|RID:)/ => :RID
          }

            ext_req_attribute = csr.attributes.find do |attr| 
              ["1.2.840.113549.1.9.14", "extReq", "extensionRequest"].include?(attr.oid)
            end

            if ext_req_attribute              
              # Decode the ASN.1 to extract the individual extensions
              asn1_set = OpenSSL::ASN1.decode(ext_req_attribute.value.to_der)
              asn1_seq = asn1_set.value.first

              asn1_seq.value.each do |ext_asn1|
                extension = OpenSSL::X509::Extension.new(ext_asn1.to_der)
                
                parsed_values = extension.value.split(',').map(&:strip)

                case extension.oid
                when 'keyUsage', '2.5.29.15'
                  # Reset all key usages to false, so only the ones that the CSR requested will be activated in the form
                  ku.each_key { |k| ku[k] = false }
                  
                  parsed_values.each do |friendly_name|
                    hash_key = key_usage_map[friendly_name]
                    ku[hash_key] = true if hash_key && ku.key?(hash_key)
                  end

                when 'extendedKeyUsage', '2.5.29.37'
                  # The same for extended key usages
                  eku.each_key { |k| eku[k] = false }
                  
                  parsed_values.each do |friendly_name|
                    hash_key = extended_key_usage_map[friendly_name]
                    eku[hash_key] = true if hash_key && eku.key?(hash_key)
                  end
                
                when 'subjectAltName', '2.5.29.17'
                  extension.value.split(',').map(&:strip).each do |entry|
                    
                    # Find the pattern corresponding to the entry and extract the value in one go
                    pattern, key = SAN_PREFIX_MAP.find { |regexp, _| entry.match?(regexp) }
                    
                    # If a valid pattern is found, remove the prefix and add to the hash
                    @san[key] = entry.sub(pattern, '') if key
                  end
                end
              end
              #puts "KeyUsages Updated: #{ku}"
              #puts "ExtendedKeyUsages Updated: #{eku}"
            end
          end

          if !session[:sign].nil?
            @san = session[:sign]["subjectAltName"]
            if !session[:sign]["keyusages"].nil? and session[:sign]["keyusages"]
              session[:sign]["keyusages"].each do |sku,v|
                ku[sku] = v 
              end
            end
            
            if !session[:sign]["extendedkeyusages"].nil? and session[:sign]["extendedkeyusages"]
              session[:sign]["extendedkeyusages"].each do |seku,v|
                eku[seku] = v 
              end
            end
          end
        
          
          haml :sign, :locals => {:keyusages => ku, :extendedkeyusages => eku}
        end

        post '/admin/csrs/:cn/sign/?' do
          session.delete(:sign)
          crt_rec = RubyCA::Core::Models::Certificate.find(cn: params[:cn])
          csr_rec = RubyCA::Core::Models::Csr.find(cn: params[:cn])
          if crt_rec
            if csr_rec && csr_rec.pkey != crt_rec.pkey
              flash.next[:danger] = "A certificate with different key already exists for '#{params[:cn]}', revoke the old certificate before signing this request"
              redirect '/admin/csrs'
            end
          end
          
          intermediate_rec = RubyCA::Core::Models::Certificate.find(cn: $config['ca']['intermediate']['cn'])
          begin
            intermediate_key = OpenSSL::PKey::RSA.new intermediate_rec.pkey, params[:passphrase][:intermediate]
          rescue OpenSSL::PKey::RSAError
            session[:sign] = params
            flash.next[:danger] = "Incorrect intermediate passphrase"
            redirect "/admin/csrs/#{params[:cn]}/sign"
          end

          if crt_rec.nil?
            crt_rec = RubyCA::Core::Models::Certificate.create( cn: csr_rec.cn, pkey: csr_rec.pkey )
          end
          csr = OpenSSL::X509::Request.new csr_rec.csr
          intermediate_crt = OpenSSL::X509::Certificate.new intermediate_rec.crt
          crt = OpenSSL::X509::Certificate.new
          serial = RubyCA::Core::Models::Config.find(name: 'last_serial')
          crt.serial = serial.value.to_i + 1
          serial.value = crt.serial.to_s
          serial.save
          crt.version = 2
          crt.not_before = Time.utc(Time.now.year, Time.now.month, Time.now.day, Time.now.hour, Time.now.min,Time.now.sec)
          crt.not_after = crt.not_before + ($config['ca']['certificate']['default_expiration'] * 365 * 24 * 60 * 60 - 1) + (($config['ca']['certificate']['default_expiration'] / 4).to_int * 24 * 60 * 60)
          crt.subject = csr.subject
          crt.public_key = csr.public_key
          crt.issuer = intermediate_crt.subject
          
          crt_ef = OpenSSL::X509::ExtensionFactory.new
          crt_ef.subject_certificate = crt
          crt_ef.issuer_certificate = intermediate_crt
          crt.add_extension crt_ef.create_extension 'basicConstraints', 'CA:FALSE'
          crt.add_extension crt_ef.create_extension 'keyUsage',params[:keyusages].nil? ? "digitalSignature" : "#{params[:keyusages].map{|ku,v| "#{ku}"}.join(',')}", true
          crt.add_extension crt_ef.create_extension 'extendedKeyUsage',"#{params[:extendedkeyusages].map{|ek,v| "#{ek}"}.join(',')}" unless params[:extendedkeyusages].nil?
          crt.add_extension crt_ef.create_extension 'subjectKeyIdentifier','hash', false
          altnames = params[:subjectAltName].reject{|k,v| v.empty?}
          crt.add_extension crt_ef.create_extension 'subjectAltName',"#{altnames.map{|san,v| "#{san}:#{v}"}.join(',')}" unless altnames.empty? 
          crt.add_extension crt_ef.create_extension 'crlDistributionPoints', "#{get_crl_dist_uri(intermediate_rec.crl.id)}" unless get_crl_dist_uri(intermediate_rec.crl.id).nil?
          
          crt.sign intermediate_key, OpenSSL::Digest::SHA512.new
          crt_rec.crt = crt.to_pem
          crt_rec.save
          csr_rec.destroy
          intermediate_key = nil
          flash.next[:success] = "Created certificate for '#{crt_rec.cn}'"
          redirect '/admin/certificates'
        end
        
        #
        # Certificate Schemas
        #
        get '/admin/cschemas/?' do
          @cschemas = RubyCA::Core::Models::CertificateSchema.all
          @cschema = session[:cschema]
          haml :certificate_schemas
        end
        
        get '/admin/cschema/:id?' do
          @cschema = RubyCA::Core::Models::CertificateSchema.find(id: params[:id])
          session[:csr] = @cschema if @cschema 
          redirect '/admin/csrs'
        end
        
        post '/admin/cschemas/?' do
          session.delete(:cschema)
          params[:cschema].each do |k,v|
            if v.nil? || v.empty?
              session[:cschema] = params[:cschema]
              flash.next[:danger] = "All fields are required"
              redirect '/admin/cschemas'
            end  
          end
          cshema = RubyCA::Core::Models::CertificateSchema.create(
            o: params[:cschema][:o],
            l: params[:cschema][:l],
            st: params[:cschema][:st],
            c: params[:cschema][:c])
          cshema.save
          redirect '/admin/cschemas'
        end
        
        get '/admin/cschemas/cancel' do
          session.delete(:cschema)
          redirect '/admin/cschemas'
        end
        
        delete '/admin/cschemas/:id/?' do
          cschema = RubyCA::Core::Models::CertificateSchema.find(id: params[:id])
          cschema.destroy
          flash.next[:success] = "Deleted certificate schema for '#{cschema.o}'"
          redirect '/admin/cschemas'
        end
        
        #
        # Certificates
        #
        get '/admin/certificates/?' do
          puts 'certificates'
          @certificates = RubyCA::Core::Models::Certificate.all
          @revokeds = RubyCA::Core::Models::Revoked.all
          haml :certificates
        end
        
        get '/admin/certificates/:cn.crt' do
          crt_rec = RubyCA::Core::Models::Certificate.find(cn:  params[:cn] )
          unless crt_rec
            halt 404
          end
          content_type :crt
          crt_rec.crt
        end
        
        get '/admin/certificates/:cn/info/?' do
          crt_rec =  RubyCA::Core::Models::Certificate.find(cn:  params[:cn] )
          unless crt_rec
            halt 404
          end
          crt = OpenSSL::X509::Certificate.new crt_rec.crt
          content_type :txt
          crt.to_text
        end
        
        get '/admin/certificates/chain/:cn.crt' do
          output = ''
          output << RubyCA::Core::Models::Certificate.find(cn: params[:cn]).crt
          unless params[:cn] === $config['ca']['root']['cn'] or params[:cn] === $config['ca']['intermediate']['cn']
            output << RubyCA::Core::Models::Certificate.find(cn: $config['ca']['intermediate']['cn']).crt
          end
          unless params[:cn] === $config['ca']['root']['cn']
            output << RubyCA::Core::Models::Certificate.find(cn: $config['ca']['root']['cn']).crt
          end
          content_type :crt
          output
        end
        
        get '/admin/certificates/:cn.pem' do
          if params[:cn] === $config['ca']['root']['cn']
            halt 404
          end
          crt_rec = RubyCA::Core::Models::Certificate.find(cn: params[:cn])
          content_type :pem
          crt_rec.pkey
        end
        
        get '/admin/certificates/decrypted/:cn.pem' do
          @crt = RubyCA::Core::Models::Certificate.find(cn: params[:cn])
          if @crt.cn === $config['ca']['root']['cn'] or @crt.cn === $config['ca']['intermediate']['cn']
            flash.next[:danger] = "Root or intermediate decrypted private key are disabled"
            redirect '/admin/certificates'
          else
            haml :rsadecrypt
          end
        end
        
        post '/admin/certificates/decrypted/:cn.pem' do   
          crt_rec = RubyCA::Core::Models::Certificate.find(cn: params[:cn])
          if crt_rec.cn === $config['ca']['root']['cn'] or crt_rec.cn === $config['ca']['intermediate']['cn']
            flash.next[:danger] = "Root or intermediate decrypted private key are disabled"
            redirect '/admin/certificates'
          else
            begin
              deckey = OpenSSL::PKey::RSA.new crt_rec.pkey, params[:passphrase][:certificate]
              session[:download_cont] = deckey.to_pem
              session[:download_cont_type] = :pem
              @download_url = "/admin/download/#{params[:cn]}.pem"
              haml :download
              
            rescue OpenSSL::PKey::RSAError
              flash.next[:danger] = "Incorrect certificate passphrase"
              redirect "/admin/certificates/decrypted/#{params[:cn]}.pem"
            end
          end
        end

        get '/admin/certificates/:cn.p12' do
          @crt = RubyCA::Core::Models::Certificate.find(cn: params[:cn])
          if @crt.cn === $config['ca']['root']['cn'] or @crt.cn === $config['ca']['intermediate']['cn']
            flash.next[:danger] = "Root or intermediate pkcs12 certificates are disabled"
            redirect '/admin/certificates'
          else
            haml :pkcs12
          end
        end
        
        post '/admin/certificates/:cn.p12' do
          crt_rec = RubyCA::Core::Models::Certificate.find(cn: params[:cn])

          root_ca = OpenSSL::X509::Certificate.new RubyCA::Core::Models::Certificate.find(cn: $config['ca']['root']['cn']).crt
          root_int_ca = OpenSSL::X509::Certificate.new RubyCA::Core::Models::Certificate.find(cn: $config['ca']['intermediate']['cn']).crt
          
          if crt_rec.cn === $config['ca']['root']['cn'] or crt_rec.cn === $config['ca']['intermediate']['cn']
            flash.next[:danger] = "Root or intermediate pkcs12 certificates are disabled"
            redirect '/admin/certificates'
          else
            crt = OpenSSL::X509::Certificate.new crt_rec.crt
            begin
              deckey = OpenSSL::PKey::RSA.new crt_rec.pkey, params[:passphrase][:certificate]
            rescue OpenSSL::PKey::RSAError
              flash.next[:danger] = "Incorrect certificate passphrase"
              redirect "/admin/certificates/#{params[:cn]}.p12"             
            end
            
            begin
              if params[:passphrase][:legacypbe] === 'on'
                p12 = legacy_pkcs12(params[:passphrase][:certificate], params[:cn], crt_rec.pkey, crt, [root_ca, root_int_ca])
              else
                p12 = OpenSSL::PKCS12.create(params[:passphrase][:certificate], params[:cn], deckey, crt, [root_ca, root_int_ca])
              end
              
              session[:download_cont] = p12.to_der
              session[:download_cont_type] = :p12
              @download_url = "/admin/download/#{params[:cn]}.p12"
              haml :download
              
            rescue OpenSSL::PKCS12::PKCS12Error
              flash.next[:danger] = "Error in pkcs12 generation"
              redirect "/admin/certificates/#{params[:cn]}.p12"
            end
          end
        end

        get '/admin/certificates/:cn/renew/?' do
          @crt = RubyCA::Core::Models::Certificate.find(cn: params[:cn])
          haml :certificate_renew
        end

        post '/admin/certificates/:cn/renew/?' do
          crt_rec = RubyCA::Core::Models::Certificate.find(cn: params[:cn])          
          if crt_rec.cn === $config['ca']['root']['cn'] || crt_rec.cn === $config['ca']['intermediate']['cn']
            flash.next[:danger] = "Root and Intermediate renew certificate are disabled on web interface."
            redirect '/admin/certificates'
          end
          if RubyCA::Core::Models::Csr.find(cn: params[:cn])
            flash.next[:danger] = "A certificate signing request already exists for <strong>'Common Name: #{cn}'</strong>"
            redirect '/admin/csrs'
          end

          begin
            deckey = OpenSSL::PKey::RSA.new crt_rec.pkey, params[:passphrase]
          rescue OpenSSL::PKey::RSAError
            flash.next[:danger] = "Incorrect key passphrase"
            redirect "/admin/certificates/#{params[:cn]}/renew"
          end

          current_crt = OpenSSL::X509::Certificate.new crt_rec.crt
          fields = {}
          current_crt.subject.to_a.each do |oid, value, _type|
            fields[oid] = value if %w[CN O L ST C].include?(oid)
          end

          
          csr_rec = RubyCA::Core::Models::Csr.create(
            cn: fields["CN"],
            o: fields["O"],
            l: fields["L"],
            st: fields["ST"],
            c: fields["C"] )
              
          ext_factory = OpenSSL::X509::ExtensionFactory.new
          ext_factory.subject_certificate = current_crt

          csr_extensions = current_crt.extensions.map do |ext|
            ext_value = ext.value
            # If the extension is subjectAltName, we need to ensure that the value is in the correct format for the CSR
            if ['subjectAltName', '2.5.29.17'].include?(ext.oid)
              ext_value = ext_value.gsub('IP Address:', 'IP:')
                                  .gsub('Registered ID:', 'RID:')
            end
            # The value is a comma-separated list of SANs, we need to ensure that each
            ext_factory.create_ext(ext.oid, ext_value, ext.critical?)
          end

          ext_req_attribute = OpenSSL::X509::Attribute.new(
            "1.2.840.113549.1.9.14", # extensionRequest OID
            OpenSSL::ASN1::Set.new([OpenSSL::ASN1::Sequence.new(csr_extensions)])
          )
                    
          csr_rec.pkey = crt_rec.pkey
          csr = OpenSSL::X509::Request.new
          csr.version = 0
          csr.subject = current_crt.subject
          csr.add_attribute(ext_req_attribute)
          csr.public_key = deckey.public_key
          csr.sign deckey, OpenSSL::Digest::SHA512.new
          csr_rec.csr = csr.to_pem
          csr_rec.save
          flash.next[:success] = "Created certificate signing request for <strong>'#{csr_rec.cn}'</strong>"
          redirect '/admin/csrs'
        end
        
        get '/admin/certificates/:cn.zip' do
          @crt = RubyCA::Core::Models::Certificate.find(cn: params[:cn])
          if @crt.cn === $config['ca']['root']['cn'] or @crt.cn === $config['ca']['intermediate']['cn']
            flash.next[:danger] = "Root or intermediate pkcs12 certificates are disabled."
            redirect '/admin/certificates'
          else
            @vpn_defaults = {}
            config_vpn_defaults = RubyCA::Core::Models::Config.find(name: "vpn_defaults_server_address")
            @vpn_defaults['server_address'] = config_vpn_defaults.value unless config_vpn_defaults.nil?
            config_vpn_defaults = RubyCA::Core::Models::Config.find(name: "vpn_defaults_iface_name")
            @vpn_defaults['iface_name'] = config_vpn_defaults.value unless config_vpn_defaults.nil?
            haml :zip
          end
        end
        
        post '/admin/certificates/:cn.zip' do
          crt_rec = RubyCA::Core::Models::Certificate.find(cn: params[:cn])
          root_ca = OpenSSL::X509::Certificate.new RubyCA::Core::Models::Certificate.find(cn: $config['ca']['root']['cn']).crt
          root_int_ca = OpenSSL::X509::Certificate.new RubyCA::Core::Models::Certificate.find(cn: $config['ca']['intermediate']['cn']).crt
          
          if crt_rec.cn === $config['ca']['root']['cn'] or crt_rec.cn === $config['ca']['intermediate']['cn']
            flash.next[:danger] = "Root or intermediate pkcs12 certificates are disabled."
            redirect '/admin/certificates'
          else
            crt = OpenSSL::X509::Certificate.new crt_rec.crt
            begin
              deckey = OpenSSL::PKey::RSA.new crt_rec.pkey, params[:passphrase][:certificate]
            rescue OpenSSL::PKey::RSAError
              flash.next[:danger] = "Incorrect certificate passphrase"
              redirect "/admin/certificates/#{params[:cn]}.zip"
            end
            
            begin
              p12_pw = random_password(128)
              p12 = OpenSSL::PKCS12.create(p12_pw, params[:cn], deckey, crt, [root_ca, root_int_ca])
              
              zbuf = Zip::OutputStream.write_buffer do |out|
                out.put_next_entry("vpn/#{params[:cn]}.p12")
                out.write(p12.to_der)
                
                out.put_next_entry("vpn/install.bat")
                out.write(Haml::Template.new('core/web/views/zip/install.bat.haml').render)
                
                out.put_next_entry("vpn/remove.bat")
                out.write(Haml::Template.new('core/web/views/zip/remove.bat.haml').render)
                
                out.put_next_entry("vpn/vpn_cert_tool.ps1")
                parms = {
                  vpn_if_name: params[:ifname],
                  vpn_server_addr: params[:serveraddr],
                  epw: Base64::strict_encode64(p12_pw),
                  cn: params[:cn],
                  icn: root_int_ca.subject.to_a.assoc('CN')&.at(1),
                  rcn: root_ca.subject.to_a.assoc('CN')&.at(1)
                }
                out.write(Haml::Template.new('core/web/views/zip/vpn_cert_tool.ps1.haml').render(Object.new, parms))
              end
              
              session[:download_cont] = zbuf.string
              session[:download_cont_type] = :zip
              @download_url = "/admin/download/#{params[:cn]}.zip"
              haml :download
              
            rescue OpenSSL::PKCS12::PKCS12Error
              flash.next[:danger] = "Cannot generate zip file."
              redirect "/admin/certificates/#{params[:cn]}.zip"
            end
          end
        end
        
        get '/admin/certificates/:cn/chpwd?' do
          @crt = RubyCA::Core::Models::Certificate.find(cn: params[:cn])
          if @crt.cn === $config['ca']['root']['cn'] 
            flash.next[:danger] = "Cannot change the root password"
            redirect '/admin/certificates'
          end
          haml :chpwd
        end
        
        post '/admin/certificates/:cn/chpwd' do
          currpw = params[:passphrase][:current]
          newpw = params[:passphrase][:new]
          confirmpw = params[:passphrase][:confirm]
          
          if currpw.nil? || newpw.nil? || confirmpw.nil? || currpw.empty? || newpw.empty? || confirmpw.empty?
            flash.next[:danger] = "Current password, new password and confirm password can't be empty."
            redirect "/admin/certificates/#{params[:cn]}/chpwd"
          end
            
          unless newpw == confirmpw
            flash.next[:danger] = "Password and confirm password does not match."
            redirect "/admin/certificates/#{params[:cn]}/chpwd"
          end
                      
          crt_rec = RubyCA::Core::Models::Certificate.find(cn: params[:cn])
          if crt_rec.cn === $config['ca']['root']['cn']
            flash.next[:danger] = "Root private key password change are disabled."
            redirect '/admin/certificates'
          else
            begin
              deckey = OpenSSL::PKey::RSA.new crt_rec.pkey, params[:passphrase][:current]              
            rescue OpenSSL::PKey::RSAError
              flash.next[:danger] = "Incorrect key passphrase"
              redirect "/admin/certificates/#{params[:cn]}/chpwd"
            end
            
            cipher = OpenSSL::Cipher.new $default_cipher
            crt_rec.pkey = deckey.export(cipher, newpw)
            crt_rec.save
            flash.next[:success] = "Key password changed for '#{crt_rec.cn}'"
            redirect '/admin/certificates'
          end
        end
        
        get '/admin/certificates/:cn/revoke/?' do
          @crt = RubyCA::Core::Models::Certificate.find(cn: params[:cn])
          if @crt.cn === $config['ca']['root']['cn'] or @crt.cn === $config['ca']['intermediate']['cn']
            flash.next[:danger] = "Cannot revoke the root or intermediate certificates"
            redirect '/admin/certificates'
          end
          haml :revoke
        end
        
        delete '/admin/certificates/:cn/revoke/?' do
          crt_rec = RubyCA::Core::Models::Certificate.find(cn: params[:cn])
          if crt_rec.cn === $config['ca']['root']['cn'] or crt_rec.cn === $config['ca']['intermediate']['cn']
            flash.next[:danger] = "Cannot revoke the root or intermediate certificates"
            redirect '/admin/certificates'
          end
          crt = OpenSSL::X509::Certificate.new RubyCA::Core::Models::Certificate.find(cn: crt_rec.cn).crt
          revoked = OpenSSL::X509::Revoked.new
          revoked.serial = crt.serial
          revoked.time = Time.now
          intermediate_rec = RubyCA::Core::Models::Certificate.find(cn: $config['ca']['intermediate']['cn'])
          begin
            intermediate_key = OpenSSL::PKey::RSA.new intermediate_rec.pkey, params[:passphrase][:intermediate]
          rescue OpenSSL::PKey::RSAError
            flash.next[:danger] = "Incorrect intermediate passphrase"
            redirect "/admin/certificates/#{params[:cn]}/revoke"
          end

          crl = OpenSSL::X509::CRL.new intermediate_rec.crl.data
          crl.add_revoked revoked
          crl.last_update = Time.now
          crl.next_update = Time.now + 60 * 60 * 24 * 30
          crl.sign intermediate_key, OpenSSL::Digest::SHA512.new
          intermediate_key = nil
          intermediate_rec.crl.data = crl.to_pem
          intermediate_rec.save
          @revoked_rec = RubyCA::Core::Models::Revoked.create(cn: crt_rec.cn, pkey: crt_rec.pkey, crt: crt_rec.crt )
          @revoked_rec.save
          crt_rec.destroy
          flash.next[:success] = "Revoked certificate for '#{crt_rec.cn}'"
          redirect '/admin/certificates'
        end

        get '/admin/revokeds/:cn/info/?' do
          crt_rec =  RubyCA::Core::Models::Revoked.find(cn: params[:cn] )
          unless crt_rec
            halt 404
          end
          crt = OpenSSL::X509::Certificate.new crt_rec.crt
          content_type :txt
          crt.to_text
        end
        
        delete '/admin/revokeds/:id/?' do
          revoked_rec = RubyCA::Core::Models::Revoked.find(id: params[:id])
          revoked_rec.destroy
          flash.next[:success] = "Removed revoked certificate for '#{revoked_rec.id}: #{revoked_rec.cn}'"
          redirect '/admin/certificates'
        end

        get '/admin/certificates/:cn/unrevoke' do
          @crt = RubyCA::Core::Models::Revoked.find(cn: params[:cn])
          haml :unrevoke
        end

        post '/admin/certificates/:cn/unrevoke' do
          revoked_cert_rec = RubyCA::Core::Models::Revoked.find(cn: params[:cn])
          crt = OpenSSL::X509::Certificate.new revoked_cert_rec.crt

          intermediate_rec = RubyCA::Core::Models::Certificate.find(cn: $config['ca']['intermediate']['cn'])
          intermediate = OpenSSL::X509::Certificate.new intermediate_rec.crt
          crl = OpenSSL::X509::CRL.new intermediate_rec.crl.data

          new_revoked = crl.revoked.reject do |revoked_cert|
            revoked_cert.serial.to_i == crt.serial.to_i
          end

          new_crl = OpenSSL::X509::CRL.new
          new_crl.version = 1
          new_crl.issuer = intermediate.subject
          new_crl.last_update = Time.now
          new_crl.next_update = Time.now + 60 * 60 * 24 * 30

          new_revoked.each do |r| 
            new_crl.add_revoked(r)
          end

          begin
            intermediate_key = OpenSSL::PKey::RSA.new intermediate_rec.pkey, params[:passphrase][:intermediate]
          rescue OpenSSL::PKey::RSAError
            flash.next[:danger] = "Incorrect intermediate passphrase"
            redirect "/admin/certificates/#{params[:cn]}/unrevoke"
          end

          new_crl.sign intermediate_key, OpenSSL::Digest::SHA512.new
          intermediate_key = nil
          intermediate_rec.crl.data = new_crl.to_pem
          intermediate_rec.crl.save

          #move revoked cert to certificates
          new_crt = RubyCA::Core::Models::Certificate.create(cn: revoked_cert_rec.cn, pkey: revoked_cert_rec.pkey, crt: revoked_cert_rec.crt)
          new_crt.save

          new_crt = RubyCA::Core::Models::Certificate.find(cn: revoked_cert_rec.cn)

          if (Digest::SHA256.hexdigest(new_crt.crt) != Digest::SHA256.hexdigest(revoked_cert_rec.crt) or Digest::SHA256.hexdigest(new_crt.pkey) != Digest::SHA256.hexdigest(revoked_cert_rec.pkey))
            flash.next[:danger] = "Unrevoked certificate for '#{revoked_cert_rec.cn}' does not match the revoked certificate. Unrevocation failed."
            redirect "/admin/certificates/#{params[:cn]}/unrevoke"
          end
          revoked_cert_rec.destroy
          flash.next[:success] = "Unrevoked certificate for '#{revoked_cert_rec.cn}'"
          redirect '/admin/certificates'
        end
        
        #
        # Download
        #
        get '/admin/download/:url' do
          if session[:download_cont]
            content = session.delete(:download_cont)
            if session[:download_cont_type]
              download_cont_type = session.delete(:download_cont_type)
            else
              download_cont_type = "application/octet-stream"
            end
            content_type download_cont_type
            content
          else
            flash.next[:danger] = "Session expired. Download content not found! Try again..."
            redirect '/admin/certificates'
          end
        end
        
        
        not_found do
          haml :not_found
        end
        
=begin
        get '/admin/dh.pem' do
          # ATTENTION
          # Be carefull. This is a experimental issue.
          # DH generation is very slow
          # Needs implementation to generate and save it on db
          
          dh = OpenSSL::PKey::DH.new(2048)
          content_type :pem
          dh.public_key.to_pem #you may send this publicly to the participating party
          
          #dh2 = OpenSSL::PKey::DH.new(der)
          #dh2.generate_key! #generate the per-session key pair
          #symm_key1 = dh1.compute_key(dh2.pub_key)
          #symm_key2 = dh2.compute_key(dh1.pub_key)
          #puts symm_key1 == symm_key2 # => true
        end
=end
        
        
      end
    end
  end
end