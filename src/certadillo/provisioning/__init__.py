"""Push provisioning: Certadillo installs certificates where they are used.

An app owner binds a certificate to a place on a target (a load balancer, a
host over SSH, a Kubernetes cluster, a cloud certificate store). Certadillo
then issues the certificate under the app's policy, installs it, checks that
the endpoint really serves it, and renews it before it expires. Pull
enrollment (ACME, EST, SCEP, CMP) stays the default for anything that can run
a client; this covers what cannot.
"""
