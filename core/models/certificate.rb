if __FILE__ == $0 then abort 'This file forms part of RubyCA and is not designed to be called directly. Please run ./RubyCA instead.' end

module RubyCA
  module Core
    module Models

      class Certificate < Sequel::Model(:certificates)
        one_to_one :crl
      end
    end
  end
end
