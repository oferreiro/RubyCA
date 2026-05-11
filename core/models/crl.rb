if __FILE__ == $0 then abort 'This file forms part of RubyCA and is not designed to be called directly. Please run ./RubyCA instead.' end

module RubyCA
  module Core
    module Models    
      class Crl < Sequel::Model(:crls)
        many_to_one :certificate
      end
    end
  end
end