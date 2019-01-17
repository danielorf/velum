#!/usr/bin/env ruby
require 'openssl'

class CA

  @@ca_pass   = 'linux'
  @@ca_serial = 492113 # random number between 2^10 and 2^30

  # note on the subject/issuer fields:
  # These fields are an X.501 Name, which is an "RDN sequence"

  def initialize(bits=4096, subject)
    # generate CA key (no password in this form)
    @key = OpenSSL::PKey::RSA.new bits
    @cert = OpenSSL::X509::Certificate.new
    @cert.version = 2 # cf. RFC 5280 - to make it a "v3" certificate
    @cert.serial = @@ca_serial += 1
    @cert.subject = OpenSSL::X509::Name.parse subject
    @cert.issuer = @cert.subject # root CA's are "self-signed"
    @cert.public_key = @key.public_key
    @cert.not_before = Time.now
    @cert.not_after = @cert.not_before + 2 * 365 * 24 * 60 * 60 # 2 years
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = @cert
    ef.issuer_certificate = @cert
    @cert.add_extension(ef.create_extension("basicConstraints","CA:TRUE",true))
    @cert.add_extension(ef.create_extension("keyUsage","keyCertSign, cRLSign", true))
    @cert.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
    @cert.add_extension(ef.create_extension("authorityKeyIdentifier","keyid:always",false))
    #@cert.sign(@key, OpenSSL::Digest::SHA256.new)
  end

  # accessors for literal objects for Ruby-based use
  attr_reader :key
  attr_reader :cert
  def ca_pass
    @@ca_pass
  end

  # need string representations for use in files
  def key_pem
    @key.to_pem('aes256', @@ca_pass)
  end

  def cert_pem
    @cert.to_pem
  end

  # used by the server cert to keep serials increasing
  def assign_serial
    @@ca_serial += 1
  end

  def _get_parent_certs
    r = []
    if @ca
      r = @ca.get_parent_certs
    end
    r.push( @cert )
    r
  end

  # return the cert store object containing this CA and all parents
  def cert_chain
    cert_store = OpenSSL::X509::Store.new
    for cert in _get_parent_certs
      cert_store.add_cert cert
    end
    cert_store
  end

  # return the same chain as cert_chain, but in a PEM string format
  def cert_chain_pem
    r = ""
    for cert in _get_parent_certs
      r += cert.to_pem
    end
    r
  end
end

class RootCA < CA

  def initialize(bits=4096, subject="C=US, ST=IL, O=Danny Sauer dot com, OU=Danny Sauer dot com Certificate Authority, CN=Danny Sauer dot com Root CA/emailAddress=dsauer@suse.com")
    super(bits, subject)
    @cert.sign(@key, OpenSSL::Digest::SHA256.new)
  end

  
end

class IntermediateCA < CA
  @@ilevel = 0

  def initialize(ca, bits=4096, subject="C=US, ST=IL, O=Danny Sauer dot com, OU=Danny Sauer dot com Certificate Authority, CN=Danny Sauer dot com Intermediate CA level %s/emailAddress=dsauer@suse.com" % (@@ilevel+=1))
    @ca = ca
    super(bits, subject)
    @cert.sign(@ca.key, OpenSSL::Digest::SHA256.new)
  end
end

class ServerCert
  def initialize(
    ca,
    altname_list=nil,
    start_time=Time.now,  # Note that nil will cause creation to fail (dates are required)
    lifetime_secs=1 * 365 * 24 * 60 * 60 # 1 year validity
  )
    @ca = ca

    @key  = OpenSSL::PKey::RSA.new 2048
    @cert = OpenSSL::X509::Certificate.new
    @cert.version = 2 # must be 2
    @cert.serial = @ca.assign_serial
    @cert.subject = OpenSSL::X509::Name.parse "/DC=org/DC=ruby-lang/CN=Ruby certificate"
    @cert.issuer = @ca.cert.subject # CA is the issuer
    @cert.public_key = @key.public_key
    @cert.not_before = start_time
    lifetime_secs = lifetime_secs ? lifetime_secs : 1
    @cert.not_after = @cert.not_before + lifetime_secs 
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = @cert
    ef.issuer_certificate = @ca.cert
    @cert.add_extension(ef.create_extension("keyUsage","digitalSignature", true))
    @cert.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
    if altname_list
      @cert.add_extension(ef.create_extension("subjectAltName", altname_list.join(',')))
    end
    @cert.sign(@ca.key, OpenSSL::Digest::SHA256.new)
  end

  # accessors for literal objects for Ruby-based use
  attr_reader :cert
  attr_reader :key

  # PEM-formatted strings for external file-based use
  # return cert and key with no password
  def key_pem
    @key.to_pem
  end

  # same, but return the key with a password applied
  def key_pem_encrypted(pass=@ca.ca_pass)
    @key.to_pem('aes256', @ca.ca_pass)
  end

  def cert_pem
    @cert.to_pem
  end

  # cert and key contatenated; no password on key
  def pem
    self.cert_pem + self.key_pem
  end

  # cert and key contatenated; password on key
  def pem_encrypted(pass=@ca.ca_pass)
    self.cert_pem + self.key_pem_encrypted(pass)
  end

  # maybe useful later?
  def re_sign
    @cert.sign(@ca.key, OpenSSL::Digest::SHA256.new)
  end
end

# testing!
if false
  ca = RootCA.new(1024)
  ica1 = IntermediateCA.new(ca, 1024)
  ica2 = IntermediateCA.new(ica1, 1024)
  crt1 = ServerCert.new(ca) # basic server cert signed by the root CA
  crt2 = ServerCert.new(    # expired server cert w/ altnames signed by intermediate CA
    ica1,
    [ "DNS:host1",
      "DNS:host2",
      "IP:1.2.3.4"
    ],
    start_time=Time.now-14*24*60*60,
    lifetime_secs=5*24*60*60
  )

  #puts ca.key_pem
  #puts ca.cert_pem
  #puts ica1.cert_pem
  #puts ica2.cert_pem
  #puts ica2.cert_chain_pem
  #puts crt1.pem
  puts crt2.pem
end
