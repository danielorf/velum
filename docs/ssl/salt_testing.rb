#!/usr/bin/env ruby
################################################################################
# Generate the Velumdex/k8sapi certs for testing
#
################################################################################

require './gen_certs'

ca = RootCA.new(1024)
ica = IntermediateCA.new(ca, 1024)

# velum
# todo: generate expired and valid certs

altname_list = {
 "velum": [
    "DNS:admin",
    "DNS:admin.infra.caasp.local",
    "DNS:b34af80fcc9e4a59ad14c1c2e1f54313",
    "DNS:b34af80fcc9e4a59ad14c1c2e1f54313.infra.caasp.local",
    "DNS:admin.devenv.caasp.suse.net",
    "IP:10.17.1.0"
  ],
  # node name can't possibly be needed; generated on one node but used on many
  "dex": [
    #"DNS:master-2",
    #"DNS:master-2.infra.caasp.local",
    #"DNS:61a89c5405fa405e8fb6a2904c139824",
    #"DNS:61a89c5405fa405e8fb6a2904c139824.infra.caasp.local",
    "DNS:kubernetes",
    "DNS:kubernetes.default",
    "DNS:kubernetes.default.svc",
    "DNS:api",
    "DNS:api.infra.caasp.local",
    "DNS:kube-api-x3.devenv.caasp.suse.net",
    #"IP Address:172.24.0.1",
    "DNS:dex",
    "DNS:dex.kube-system",
    "DNS:dex.kube-system.svc",
    "DNS:dex.kube-system.svc.infra.caasp.local",
    "DNS:kubernetes.default.svc.cluster.local"
  ],
  # I'm pretty sure admin hostname is needed
  # todo: are master hostnames used? Probably not... 
  "kube-api": [
    "DNS:admin",
    "DNS:admin.infra.caasp.local",
    #"DNS:b34af80fcc9e4a59ad14c1c2e1f54313",
    #"DNS:b34af80fcc9e4a59ad14c1c2e1f54313.infra.caasp.local",
    "DNS:master-0",
    "DNS:master-0.infra.caasp.local",
    #"DNS:f46276632b5543d998914a9504d72596",
    #"DNS:f46276632b5543d998914a9504d72596.infra.caasp.local",
    "DNS:master-1",
    "DNS:master-1.infra.caasp.local",
    "DNS:master-2",
    "DNS:master-2.infra.caasp.local",
    "DNS:kubernetes",
    "DNS:kubernetes.default",
    "DNS:kubernetes.default.svc",
    "DNS:api",
    "DNS:api.infra.caasp.local",
    "DNS:kube-api-x3.devenv.caasp.suse.net",
    "DNS:kubernetes.default.svc.cluster.local",
    "IP:172.24.0.1"
  ]
}

File.write( 'ca.crt', ca.cert_pem )
File.write( 'intermediate_ca.crt', ica.cert_pem )
altname_list.each do |svc, altnames|
  crt = ServerCert.new(
    ica,
    altnames,
    start_time=Time.now,
    lifetime_secs=1*365*24*60*60
    )
  File.write( "#{svc}.crt", crt.cert_pem )
  File.write( "#{svc}.key", crt.key_pem )
  exp_crt = ServerCert.new(
    ica,
    altnames,
    start_time=Time.now - 14*24*60*60,   # 14 days ago
    lifetime_secs=7*24*60*60,            # 7 days lifetime
    )
  File.write( "#{svc}-expired.crt", exp_crt.cert_pem )
  File.write( "#{svc}-expired.key", exp_crt.key_pem )
end
