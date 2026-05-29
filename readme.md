# RubyCA

## About

RubyCA is a simple certificate authority manager written in Ruby.

This is a fork from https://github.com/phillcampbell/RubyCA

It is designed for internal use as an alternative to using self-signed certificates. Install and trust the root certificate in your clients, and any certificates you create will just work, no more browser warnings.

## Development

RubyCA is currently in development, and not all features are implemented.

Currently, RubyCA will generate root and intermediate CA certificates. The web UI can be used to manage signing requests, certificates, and revocations, as well as to download certificates and keys and serve the certificate revocation list.

In the future, the web UI will support the Online Certificate Status Protocol (OCSP).

Currently, there isn’t much error checking; this will be added in the future.

Pull requests welcome.

## Usage

Clone and enter the repository

    $ git clone https://github.com/oferreiro/RubyCA
    $ cd RubyCA

Use bundle to install dependencies.

    $ bundle install

Create the ./config/rubyca.yml file and edit to suit your requirements.

    $ cp ./config/rubyca.yml.sample ./config/rubyca.yml
    $ nano ./config/rubyca.yml

Migrate the database
    $ bundle exec rake db:migrate

If you are migrating from the 2.x.x version, use:

    $ bundle exec rake db:migrate_dm_to_sequel
    $ bundle exec rake db:migrate_dm_crls_to_sequel

RubyCA must be started as root on the first run to generate the CA certificates.
Basically, it is only to save the root-ca private key in the private directory with root read-only(400) permissions.

    $ sudo ./RubyCA
    or
    $ sudo bundle exec rake ca:setup

To run in unsafe mode (-u|–unsafe) if you want to keep current user privileges on the root CA private key file.
In this case, the root-ca private key will save on the private directory root read-only(400) permissions.

    $ ./RubyCA --unsafe
    or
    $ bundle exec rake "ca:setup[unsafe]"

Visit http://host:port/admin to manage certificates

## Tips

To run RubyCA as a daemon:

### Using Puma:

    $ cp ./distrib/puma/puma-sample.rb ./config/puma.rb
    nano ./config/puma.rb

RubyCA must be started with:

    $ bundle exec puma -C ./config/puma.rb

### Note:
The first run still needs RubyCA run as root or with the “unsafe” param to be able to generate the CA certificates.