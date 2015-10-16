# Install-RDPCertificate

The Install-RDPCertificate function can be used to replace a computer's self-signed RDP certificate with a trusted certificate, either from a third-party certificate authority, or from an organization's internal certificate authority. The certificate must be in PFX format and protected with a password.

This script was inspired by Ryan Mangan's RDS 2012 Session Host Certificate Configuration script - https://gallery.technet.microsoft.com/RDS-2012-Session-Host-fbb54ff9.

I improved upon Ryan's script by allowing you to push the certificate to multiple remote computer simultaneously, as opposed to having to run the script locally on each RDSH server.

You need to supply the following information to the script:

Path to the certificate in PFX format.
Password to the certificate.
Optional list of computer names. If not specified, the script will run against the local computer.
Optional ListenerName - in case your organization customized the name of the RDP listener.

Enjoy!

Tom Murphy
http://blog.tmurphy.org
