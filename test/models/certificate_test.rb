require_relative '../test_helper'

module RubyCA
  module Core
    module Models
      class CertificateTest < Minitest::Test
        def setup
          DB[:crls].delete
          DB[:certificates].delete
        end

        def test_certificate_has_one_to_one_crl_association
          certificate = Certificate.create(cn: 'example.com', crt: 'pem-data', pkey: 'private-key')
          crl = Crl.create(data: 'crl-data', certificate_id: certificate.id)

          assert_equal crl, certificate.crl
          assert_equal certificate, crl.certificate
        end
      end
    end
  end
end
