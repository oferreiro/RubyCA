if __FILE__ == $0 then abort 'This file forms part of RubyCA and is not designed to be called directly. Please run ./RubyCA instead.' end

module RubyCA
  module Core
    module Models

      class Certificate < Sequel::Model(:certificates)
        one_to_one :crl
        def self.get_by_cn(cn)
          self.where(cn: cn).first unless self.count == 0
        end

      end
    end
  end
end
