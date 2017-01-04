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
        set :bind, CONFIG['web']['interface']
        set :port, CONFIG['web']['port']
        set :haml, layout: :layout
        mime_type :pem, 'pem/pem'
        
        keyusages = {
          'nonRepudiation' => false,
          'digitalSignature' => true,
          'dataEncipherment' => true,
          'keyEncipherment' => false,
          'keyAgreement' => false,
          'cRLSign' => false
        }
        
        extendedkeyusages = { 
          'clientAuth' => true,
          'serverAuth' => false,
          'emailProtection' => false,
          'ipsecEndSystem' => false,
          'ipsecTunnel' => false,
          'ipsecUser' => false,
          #'1.3.6.1.5.5.8.2.2' => false #iKEIntermediate
        }
        
        helpers do
          
          def hosts_allowed?
            allowed = false
            remote_addr = request.env['HTTP_X_REAL_IP'] || request.env['HTTP_X_FORWARDED_FOR'] || request.ip
            remote_ip = IPAddress remote_addr
            
            CONFIG['web']['admin']['allowed_ips'].each do |allowed_ip|
              allow = IPAddress allowed_ip
              if (remote_ip.ipv4? && allow.ipv4?) || (remote_ip.ipv6? && allow.ipv6?)
                if allow.include? remote_ip
                  allowed = true
                  break
                end
              end
            end
            allowed
          end
          
          def protected!
            authcfg = CONFIG['web']['admin']['auth']
            @user = authcfg['username'] unless authcfg.nil? || authcfg.empty?
            @pass = authcfg['password'] unless authcfg.nil? || authcfg.empty?
            permit_auth = authcfg['enable'] && !(authcfg.nil? || authcfg.empty? || @user.nil? || @user.empty? || @pass.nil? || @pass.empty?)
            
            unless authorized?
              if permit_auth
                response['WWW-Authenticate'] = %(Basic realm="Restricted Area")
              end
              throw(:halt, [401, "Not authorized\n"])
            end
          end

          def authorized?
            auth = Rack::Auth::Basic::Request.new(request.env)
            auth.provided? && auth.basic? && auth.credentials && @user == Digest::MD5.hexdigest(auth.credentials[0]) && @pass == Digest::MD5.hexdigest(auth.credentials[1])
          end
          
          def get_crl_info
            crl_rec = RubyCA::Core::Models::CRL.last.crl
            crl = OpenSSL::X509::CRL.new crl_rec
            issuer = {}
            crl.issuer().to_s.split("/").each do |x|
              if x!=""
                k,v = x.split("=")
                issuer[k] = v
              end
            end
            crl_info = {}
            crl_info[:issuer] = issuer
            crl_info[:last_update] = Time.parse(crl.last_update().to_s)
            crl_info[:next_update] = Time.parse(crl.next_update().to_s)
            crl_info[:expired] = false
            
            if Time.now.utc > crl_info[:next_update]
              crl_info[:expired] = true
            end
            crl_info
          end
        end
                  
        before '/admin*' do
          unless hosts_allowed?
            protected!
          end
        end
        
        get '/' do
          redirect '/admin'
        end
        
        get '/ca.crl' do
          @crl = OpenSSL::X509::CRL.new RubyCA::Core::Models::CRL.last.crl
          content_type :crl
          @crl.to_der
        end
                  
        get '/admin/?' do
          haml :admin
        end
        
        get '/admin/setup' do
          @authcfg = CONFIG['web']['admin']['auth']
          haml :setup
        end
        
        
        post '/admin/setup' do
          CONFIG['web']['admin']['auth'] ||={}
          username = params[:authcfg][:username]
          password = params[:authcfg][:password]
          enable = params[:authcfg][:enable] == "1" ? true : false
          
          CONFIG['web']['admin']['auth']['username'] = Digest::MD5.hexdigest(username) unless username.nil? || username.empty?
          CONFIG['web']['admin']['auth']['password'] = Digest::MD5.hexdigest(password) unless password.nil? || password.empty?
          CONFIG['web']['admin']['auth']['enable'] = enable
          File.open($root_dir+'/config.yaml', 'w') {|f| YAML.dump(CONFIG, f) } #Store
          flash.next[:success] = "Admin authentication settings stored"
          redirect '/admin/setup'
        end
                
        get '/admin/crl' do
          @crl_info = get_crl_info 
          haml :crl
        end
        
        get '/admin/crl/info' do
          crl_rec = RubyCA::Core::Models::CRL.last
          crl = OpenSSL::X509::CRL.new crl_rec.crl
          content_type :txt
          crl.to_text 
        end
        
        get '/admin/crl/renew' do
          @crl_info = get_crl_info 
          if !@crl_info[:expired]
            flash.next[:danger] = "CRL renew is not necessary."
            redirect '/admin/crl'
          else
            haml :crlrenew
          end
        end
        
        post '/admin/crl/renew' do                        
          intermediate = RubyCA::Core::Models::Certificate.get_by_cn(CONFIG['ca']['intermediate']['cn'])
          begin
            intermediate_key = OpenSSL::PKey::RSA.new intermediate.pkey, params[:passphrase][:intermediate]
          rescue OpenSSL::PKey::RSAError
            session[:sign] = params
            flash.next[:danger] = "Incorrect intermediate CA key passphrase"
            redirect "/admin/crl/renew"
          end
          intermediate_crt = OpenSSL::X509::Certificate.new intermediate.crt 
          
          crl_rec = RubyCA::Core::Models::CRL.last
          crl = OpenSSL::X509::CRL.new crl_rec.crl
          
          if Time.now.utc < Time.parse(crl.next_update().to_s)
            flash.next[:danger] = "CRL is not expired. Renew is not necessary"
            redirect '/admin/crl'
          end
          
          crl.last_update = Time.now
          crl.next_update = Time.now + 60 * 60 * 24 * 30
          crl.sign intermediate_key, OpenSSL::Digest::SHA512.new
          intermediate_key = nil
          crl_rec.crl = crl.to_pem
          crl_rec.save
          flash.next[:success] = "CRL successfully renewed"
          redirect '/admin/crl'
        end
        
        get '/admin/csrs/:cn/info' do
          csr_rec = RubyCA::Core::Models::CSR.get(params[:cn])
          csr = OpenSSL::X509::Request.new csr_rec.csr
          content_type :txt
          csr.to_text 
        end
      
        get '/admin/csrs/?' do
          @csrs = RubyCA::Core::Models::CSR.all
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
          
          if RubyCA::Core::Models::CSR.get(params[:csr][:cn])
            cn = params[:csr][:cn]
            session[:csr] = params[:csr]
            session[:csr][:cn] = nil
            flash.next[:danger] = "A certificate signing request already exists for <strong>'Common Name: =#{cn}'</strong>"
            redirect '/admin/csrs'
          end
          
          @csr = RubyCA::Core::Models::CSR.create(
              cn: params[:csr][:cn],
              o: params[:csr][:o],
              l: params[:csr][:l],
              st: params[:csr][:st],
              c: params[:csr][:c] )
              
          cipher = OpenSSL::Cipher::Cipher.new 'AES-256-CBC'
          key = OpenSSL::PKey::RSA.new 2048
          @csr.pkey = key.export(cipher, params[:csr][:passphrase])
          csr = OpenSSL::X509::Request.new
          csr.version = 2
          csr.subject = OpenSSL::X509::Name.parse "C=#{@csr.c}/ST=#{@csr.st}/L=#{@csr.l}/O=#{@csr.o}/CN=#{@csr.cn}"
          csr.public_key = key.public_key
          csr.sign key, OpenSSL::Digest::SHA512.new
          @csr.csr = csr.to_pem
          @csr.save
          flash.next[:success] = "Created certificate signing request for '#{@csr.cn}'"
          redirect '/admin/csrs'
        end
        
        get '/admin/csrs/cancel' do
          session.delete(:csr)
          redirect '/admin/csrs'
        end
        
        delete '/admin/csrs/:cn/?' do
          @csr = RubyCA::Core::Models::CSR.get(params[:cn])
          @csr.destroy
          flash.next[:success] = "Deleted certificate signing request for '#{@csr.cn}'"
          redirect '/admin/csrs'
        end
        
        get '/admin/csrs/sign/cancel' do
          session.delete(:sign)
          redirect '/admin/csrs'
        end
        
        get '/admin/csrs/:cn/sign/?' do     
          if RubyCA::Core::Models::Certificate.get_by_cn(params[:cn])
            flash.next[:danger] = "A certificate already exists for '#{params[:cn]}', revoke the old certificate before signing this request"
            redirect '/admin/csrs'
          end
          @csr = RubyCA::Core::Models::CSR.get(params[:cn])
          @sign = session[:sign]
          
          ku = keyusages.clone
          eku = extendedkeyusages.clone
          
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
          if RubyCA::Core::Models::Certificate.get_by_cn(params[:cn])
            flash.next[:danger] = "A certificate already exists for '#{params[:cn]}', revoke the old certificate before sign this request"
            redirect '/admin/csrs'
          end
          @csr = RubyCA::Core::Models::CSR.get(params[:cn])
          @intermediate = RubyCA::Core::Models::Certificate.get_by_cn(CONFIG['ca']['intermediate']['cn'])
          begin
            intermediate_key = OpenSSL::PKey::RSA.new @intermediate.pkey, params[:passphrase][:intermediate]
          rescue OpenSSL::PKey::RSAError
            session[:sign] = params
            flash.next[:danger] = "Incorrect intermediate passphrase"
            redirect "/admin/csrs/#{params[:cn]}/sign"
          end
          
          @crt = RubyCA::Core::Models::Certificate.create( cn: @csr.cn, pkey: @csr.pkey )
          csr = OpenSSL::X509::Request.new @csr.csr
          intermediate_crt = OpenSSL::X509::Certificate.new @intermediate.crt
          crt = OpenSSL::X509::Certificate.new
          @serial = RubyCA::Core::Models::Config.get('last_serial')
          crt.serial = @serial.value.to_i + 1
          @serial.value = crt.serial.to_s
          @serial.save
          crt.version = 2
          crt.not_before = Time.utc(Time.now.year, Time.now.month, Time.now.day, 00, 00, 0)
          crt.not_after = crt.not_before  + (CONFIG['certificate']['years'] * 365 * 24 * 60 * 60 - 1) + ((CONFIG['certificate']['years'] / 4).to_int * 24 * 60 * 60)
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
          
          if CONFIG['crlDist'].nil? || CONFIG['crlDist']['uri'].nil? || CONFIG['crlDist']['uri'] ===''
            crldist = "URI:http://#{CONFIG['web']['domain']}#{(':' + CONFIG['web']['port'].to_s) unless CONFIG['web']['port'] == 80}/ca.crl"  
          else
            crldist = "URI:#{CONFIG['crlDist']['uri']}"
          end
          crt.add_extension crt_ef.create_extension 'crlDistributionPoints', "#{crldist}"
          
          crt.sign intermediate_key, OpenSSL::Digest::SHA512.new
          @crt.crt = crt.to_pem
          @crt.save
          @csr.destroy
          intermediate_key = nil
          flash.next[:success] = "Created certificate for '#{@crt.cn}'"
          redirect '/admin/certificates'
        end
        
        get '/admin/certificates/?' do
          @certificates = RubyCA::Core::Models::Certificate.all
          @revokeds = RubyCA::Core::Models::Revoked.all
          haml :certificates
        end
        
        get '/admin/certificates/:cn.crt' do
          @crt = RubyCA::Core::Models::Certificate.get_by_cn( params[:cn] )
          if @crt
            content_type :crt
            @crt.crt
          else
             halt 404
          end
        end
        
        get '/admin/certificates/:cn/info/?' do
          raw =  RubyCA::Core::Models::Certificate.get_by_cn( params[:cn] )
          if raw
            crt = OpenSSL::X509::Certificate.new raw.crt
            content_type :txt
            crt.to_text 
          else
            halt 404
          end
        end
        
        get '/admin/certificates/chain/:cn.crt' do
          output = RubyCA::Core::Models::Certificate.get_by_cn(params[:cn]).crt
          unless params[:cn] === CONFIG['ca']['root']['cn'] or params[:cn] === CONFIG['ca']['intermediate']['cn']
            output << RubyCA::Core::Models::Certificate.get_by_cn(CONFIG['ca']['intermediate']['cn']).crt
          end
          unless params[:cn] === CONFIG['ca']['root']['cn']
            output << RubyCA::Core::Models::Certificate.get_by_cn(CONFIG['ca']['root']['cn']).crt
          end
          content_type :crt
          output
        end
        
        get '/admin/certificates/:cn.pem' do
          if params[:cn] === CONFIG['ca']['root']['cn']
            halt 404
          end
          @crt = RubyCA::Core::Models::Certificate.get_by_cn(params[:cn])
          content_type :pem
          @crt.pkey
        end
        
        get '/admin/certificates/decrypted/:cn.pem' do
          @crt = RubyCA::Core::Models::Certificate.get_by_cn(params[:cn])
          if @crt.cn === CONFIG['ca']['root']['cn'] or @crt.cn === CONFIG['ca']['intermediate']['cn']
            flash.next[:danger] = "Root or intermediate decrypted private key are disabled"
            redirect '/admin/certificates'
          else
            haml :rsadecrypt
          end
        end
        
        post '/admin/certificates/decrypted/:cn.pem' do   
          @crt = RubyCA::Core::Models::Certificate.get_by_cn(params[:cn])
          if @crt.cn === CONFIG['ca']['root']['cn'] or @crt.cn === CONFIG['ca']['intermediate']['cn']
            flash.next[:danger] = "Root or intermediate decrypted private key are disabled"
            redirect '/admin/certificates'
          else
            begin
              deckey = OpenSSL::PKey::RSA.new @crt.pkey, params[:passphrase][:certificate]
              content_type :pem
              deckey.to_pem
            rescue OpenSSL::PKey::RSAError
              flash.next[:danger] = "Incorrect certificate passphrase"
              redirect "/admin/certificates/decrypted/#{params[:cn]}.pem"
            end
          end
        end

        get '/admin/certificates/:cn.p12' do
          @crt = RubyCA::Core::Models::Certificate.get_by_cn(params[:cn])
          if @crt.cn === CONFIG['ca']['root']['cn'] or @crt.cn === CONFIG['ca']['intermediate']['cn']
            flash.next[:danger] = "Root or intermediate pkcs12 certificates are disabled"
            redirect '/admin/certificates'
          else
            haml :pkcs12
          end
        end
        
        post '/admin/certificates/:cn.p12' do
          @crt = RubyCA::Core::Models::Certificate.get_by_cn(params[:cn])
          rawCA = RubyCA::Core::Models::Certificate.get_by_cn(CONFIG['ca']['root']['cn']).crt
          rawintCA = RubyCA::Core::Models::Certificate.get_by_cn(CONFIG['ca']['intermediate']['cn']).crt
          root_ca = OpenSSL::X509::Certificate.new rawCA
          root_int_ca = OpenSSL::X509::Certificate.new rawintCA
          
          if @crt.cn === CONFIG['ca']['root']['cn'] or @crt.cn === CONFIG['ca']['intermediate']['cn']
            flash.next[:danger] = "Root or intermediate pkcs12 certificates are disabled"
            redirect '/admin/certificates'
          else
            raw = @crt.crt
            cert = OpenSSL::X509::Certificate.new raw
            begin
              deckey = OpenSSL::PKey::RSA.new @crt.pkey, params[:passphrase][:certificate]
            rescue OpenSSL::PKey::RSAError
              flash.next[:danger] = "Incorrect certificate passphrase"
              redirect "/admin/certificates/#{params[:cn]}.p12"
            end
            
            begin
              p12 = OpenSSL::PKCS12.create(params[:passphrase][:certificate], params[:cn], deckey, cert, [root_ca, root_int_ca])
              content_type :p12
              p12.to_der
            rescue OpenSSL::PKCS12::PKCS12Error
              flash.next[:danger] = "Error in pkcs12 generate"
              redirect "/admin/certificates/#{params[:cn]}.p12"
            end
            #redirect "/admin/certificates"
          end
        end
        
        get '/admin/certificates/:cn/revoke/?' do
          @crt = RubyCA::Core::Models::Certificate.get_by_cn(params[:cn])
          if @crt.cn === CONFIG['ca']['root']['cn'] or @crt.cn === CONFIG['ca']['intermediate']['cn']
            flash.next[:danger] = "Cannot revoke the root or intermediate certificates"
            redirect '/admin/certificates'
          end
          haml :revoke
        end
        
        delete '/admin/certificates/:cn/revoke/?' do
          @crt = RubyCA::Core::Models::Certificate.get_by_cn(params[:cn])
          if @crt.cn === CONFIG['ca']['root']['cn'] or @crt.cn === CONFIG['ca']['intermediate']['cn']
            flash.next[:danger] = "Cannot revoke the root or intermediate certificates"
            redirect '/admin/certificates'
          end
          crt = OpenSSL::X509::Certificate.new RubyCA::Core::Models::Certificate.get_by_cn(@crt.cn).crt
          revoked = OpenSSL::X509::Revoked.new
          revoked.serial = crt.serial
          revoked.time = Time.now
          @intermediate = RubyCA::Core::Models::Certificate.get_by_cn(CONFIG['ca']['intermediate']['cn'])
          begin
            intermediate_key = OpenSSL::PKey::RSA.new @intermediate.pkey, params[:passphrase][:intermediate]
          rescue OpenSSL::PKey::RSAError
            flash.next[:danger] = "Incorrect intermediate passphrase"
            redirect "/admin/certificates/#{params[:cn]}/revoke"
          end
          @crl = RubyCA::Core::Models::CRL.get(1)
          crl = OpenSSL::X509::CRL.new @crl.crl
          crl.add_revoked revoked
          crl.last_update = Time.now
          crl.next_update = Time.now + 60 * 60 * 24 * 30
          crl.sign intermediate_key, OpenSSL::Digest::SHA512.new
          intermediate_key = nil
          @crl.crl = crl.to_pem
          @crl.save
          @revokedcert = RubyCA::Core::Models::Revoked.create( cn: @crt.cn, pkey: @crt.pkey, crt: @crt.crt )
          @revokedcert.save
          @crt.destroy
          flash.next[:success] = "Revoked certificate for '#{@crt.cn}'"
          redirect '/admin/certificates'
        end
        
        delete '/admin/revokeds/:id/?' do
          @revokedcert = RubyCA::Core::Models::Revoked.get(params[:id])
          @revokedcert.destroy
          flash.next[:success] = "Removed revoked certificate for '#{@revokedcert.id}: #{@revokedcert.cn}'"
          redirect '/admin/certificates'
        end
        
        not_found do
          '404 - Not Found'
        end
      	
        get '/admin/dh.pem' do
          # ATTENTION
          # Be carefull. This is a experimental issue.
          # DH generation is very slow
          # Needs implementation of generate and save on db
          
          dh = OpenSSL::PKey::DH.new(2048)
          content_type :pem
          dh.public_key.to_pem #you may send this publicly to the participating party
          
          #dh2 = OpenSSL::PKey::DH.new(der)
          #dh2.generate_key! #generate the per-session key pair
          #symm_key1 = dh1.compute_key(dh2.pub_key)
          #symm_key2 = dh2.compute_key(dh1.pub_key)
          #puts symm_key1 == symm_key2 # => true
        end
      end
    end
  end
end
