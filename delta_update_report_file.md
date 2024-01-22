## Automatic Update:  -> 

### New Controls:
+   SV-250315 - RHEL 8 systems, versions 8.2 and above, must configure SELinux context type to allow the use of a non-default faillock tally directory.
+   SV-250316 - RHEL 8 systems below version 8.2 must configure SELinux context type to allow the use of a non-default faillock tally directory.
+   SV-250317 - RHEL 8 must not enable IPv4 packet forwarding unless the system is a router.
+   SV-251706 - The RHEL 8 operating system must not have accounts configured with blank or null passwords.
+   SV-251707 - RHEL 8 library directories must have mode 755 or less permissive.
+   SV-251708 - RHEL 8 library directories must be owned by root.
+   SV-251709 - RHEL 8 library directories must be group-owned by root or a system account.
+   SV-251710 - The RHEL 8 operating system must use a file integrity tool to verify correct operation of all security functions.
+   SV-251711 - RHEL 8 must specify the default &quot;include&quot; directory for the &#x2F;etc&#x2F;sudoers file.
+   SV-251712 - The RHEL 8 operating system must not be configured to bypass password requirements for privilege escalation.
+   SV-251713 - RHEL 8 must ensure the password complexity module is enabled in the system-auth file.
+   SV-251714 - RHEL 8 systems below version 8.4 must ensure the password complexity module in the system-auth file is configured for three retries or less.
+   SV-251715 - RHEL 8 systems below version 8.4 must ensure the password complexity module in the password-auth file is configured for three retries or less.
+   SV-251716 - RHEL 8 systems, version 8.4 and above, must ensure the password complexity module is configured for three retries or less.
+   SV-251717 - RHEL 8 must be configured in the system-auth file to prohibit password reuse for a minimum of five generations.
+   SV-251718 - The graphical display manager must not be the default target on RHEL 8 unless approved.
+   SV-254520 - RHEL 8 must prevent nonprivileged users from executing privileged functions, including disabling, circumventing, or altering implemented security safeguards&#x2F;countermeasures.
+   SV-255924 - RHEL 8 SSH server must be configured to use only FIPS-validated key exchange algorithms.
+   SV-256973 - RHEL 8 must ensure cryptographic verification of vendor software packages.
+   SV-256974 - RHEL 8 must be configured to allow sending email notifications of unauthorized configuration changes to designated personnel.
+   SV-257258 - RHEL 8 must terminate idle user sessions.


### Updated Check/Fixes:
#### Checks:
<details open>
  <summary>Click to expand.</summary>
SV-230221:
Old: 
```
Verify the version of the operating system is vendor supported.

Check the version of the operating system with the following command:

$ sudo cat /etc/redhat-release

Red Hat Enterprise Linux Server release 8.4 (Ootpa)

Current End of Extended Update Support for RHEL 8.1 is 30 November 2021.

Current End of Extended Update Support for RHEL 8.2 is 30 April 2022.

Current End of Extended Update Support for RHEL 8.4 is 30 April 2023.

Current End of Maintenance Support for RHEL 8.5 is 30 April 2022.

Current End of Extended Update Support for RHEL 8.6 is 30 April 2024.

Current End of Maintenance Support for RHEL 8.7 is 30 April 2023.

Current End of Extended Update Support for RHEL 8.8 is 30 April 2025.

Current End of Maintenance Support for RHEL 8.9 is 30 April 2024.

Current End of Maintenance Support for RHEL 8.10 is 31 May 2029.

If the release is not supported by the vendor, this is a finding.

```

Updated:
```
Verify the version of the operating system is vendor supported.

Note: The lifecycle time spans and dates are subject to adjustment.

Check the version of the operating system with the following command:

$ sudo cat /etc/redhat-release

Red Hat Enterprise Linux Server release 8.6 (Ootpa)

Current End of Extended Update Support for RHEL 8.1 is 30 November 2021.

Current End of Extended Update Support for RHEL 8.2 is 30 April 2022.

Current End of Extended Update Support for RHEL 8.4 is 31 May 2023.

Current End of Maintenance Support for RHEL 8.5 is 31 May 2022.

Current End of Extended Update Support for RHEL 8.6 is 31 May 2024.

Current End of Maintenance Support for RHEL 8.7 is 31 May 2023.

Current End of Extended Update Support for RHEL 8.8 is 31 May 2025.

Current End of Maintenance Support for RHEL 8.9 is 31 May 2024.

Current End of Maintenance Support for RHEL 8.10 is 31 May 2029.

If the release is not supported by the vendor, this is a finding.

```
---
SV-230224:
Old: 
```
Verify RHEL 8 prevents unauthorized disclosure or modification of all
information requiring at-rest protection by using disk encryption.

    If there is a documented and approved reason for not having data-at-rest
encryption, this requirement is Not Applicable.

    Verify all system partitions are encrypted with the following command:

    $ sudo blkid

    /dev/mapper/rhel-root:  UUID="67b7d7fe-de60-6fd0-befb-e6748cf97743"
TYPE="crypto_LUKS"

    Every persistent disk partition present must be of type "crypto_LUKS". If
any partitions other than pseudo file systems (such as /proc or /sys) are not
type "crypto_LUKS", ask the administrator to indicate how the partitions are
encrypted.  If there is no evidence that all local disk partitions are
encrypted, this is a finding.

```

Updated:
```
Verify RHEL 8 prevents unauthorized disclosure or modification of all information requiring at-rest protection by using disk encryption. 

If there is a documented and approved reason for not having data-at-rest encryption at the operating system level, such as encryption provided by a hypervisor or a disk storage array in a virtualized environment, this requirement is not applicable.

Verify all system partitions are encrypted with the following command:

     $ sudo blkid

     /dev/mapper/rhel-root:  UUID="67b7d7fe-de60-6fd0-befb-e6748cf97743" TYPE="crypto_LUKS"

Every persistent disk partition present must be of type "crypto_LUKS". If any partitions other than the boot partition or pseudo file systems (such as /proc or /sys) are not type "crypto_LUKS", ask the administrator to indicate how the partitions are encrypted. 

If there is no evidence that these partitions are encrypted, this is a finding.

```
---
SV-230225:
Old: 
```
Verify any publicly accessible connection to the operating system displays
the Standard Mandatory DoD Notice and Consent Banner before granting access to
the system.

    Check for the location of the banner file being used with the following
command:

    $ sudo grep -i banner /etc/ssh/sshd_config

    banner /etc/issue

    This command will return the banner keyword and the name of the file that
contains the ssh banner (in this case "/etc/issue").

    If the line is commented out, this is a finding.

    View the file specified by the banner keyword to check that it matches the
text of the Standard Mandatory DoD Notice and Consent Banner:

    "You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only. By using this IS (which includes any
device attached to this IS), you consent to the following conditions:

    -The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are
subject to routine monitoring, interception, and search, and may be disclosed
or used for any USG-authorized purpose.

    -This IS includes security measures (e.g., authentication and access
controls) to protect USG interests--not for your personal benefit or privacy.

    -Notwithstanding the above, using this IS does not constitute consent to
PM, LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services
by attorneys, psychotherapists, or clergy, and their assistants. Such
communications and work product are private and confidential. See User
Agreement for details."

    If the system does not display a graphical logon banner or the banner does
not match the Standard Mandatory DoD Notice and Consent Banner, this is a
finding.

    If the text in the file does not match the Standard Mandatory DoD Notice
and Consent Banner, this is a finding.

```

Updated:
```
Verify any publicly accessible connection to the operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting access to the system.

Check for the location of the banner file being used with the following command:

$ sudo grep -ir banner /etc/ssh/sshd_config*

banner /etc/issue

This command will return the banner keyword and the name of the file that contains the ssh banner (in this case "/etc/issue").

If the line is commented out, this is a finding.
If conflicting results are returned, this is a finding.

View the file specified by the banner keyword to check that it matches the text of the Standard Mandatory DoD Notice and Consent Banner:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

If the system does not display a graphical logon banner or the banner does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding.

If the text in the file does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding.

```
---
SV-230226:
Old: 
```
Verify RHEL 8 displays the Standard Mandatory DoD Notice and Consent Banner
before granting access to the operating system via a graphical user logon.

    Note: This requirement assumes the use of the RHEL 8 default graphical user
interface, Gnome Shell. If the system does not have any graphical user
interface installed, this requirement is Not Applicable.

    Check that the operating system displays the exact Standard Mandatory DoD
Notice and Consent Banner text with the command:

    $ sudo grep banner-message-text /etc/dconf/db/local.d/*

    banner-message-text=
    'You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only. \
    By using this IS (which includes any device attached to this IS), you
consent to the following conditions:\
    -The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.\
    -At any time, the USG may inspect and seize data stored on this IS.\
    -Communications using, or data stored on, this IS are not private, are
subject to routine monitoring, interception, and search, and may be disclosed
or used for any USG-authorized purpose.\
    -This IS includes security measures (e.g., authentication and access
controls) to protect USG interests--not for your personal benefit or privacy.\
    -Notwithstanding the above, using this IS does not constitute consent to
PM, LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services
by attorneys, psychotherapists, or clergy, and their assistants. Such
communications and work product are private and confidential. See User
Agreement for details. '

    Note: The "\" characters are for formatting only. They will not be displayed on the
graphical interface.

    If the banner does not match the Standard Mandatory DoD Notice and Consent
Banner exactly, this is a finding.

```

Updated:
```
Verify RHEL 8 displays the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system via a graphical user logon.

Note: This requirement assumes the use of the RHEL 8 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable. 

Check that the operating system displays the exact Standard Mandatory DoD Notice and Consent Banner text with the command:

$ sudo grep banner-message-text /etc/dconf/db/local.d/*

banner-message-text=
'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n-At any time, the USG may inspect and seize data stored on this IS.\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details. '

Note: The "\n " characters are for formatting only. They will not be displayed on the graphical interface.

If the banner does not match the Standard Mandatory DoD Notice and Consent Banner exactly, this is a finding.

```
---
SV-230229:
Old: 
```
Verify RHEL 8 for PKI-based authentication has valid certificates by
constructing a certification path (which includes status information) to an
accepted trust anchor.

    Check that the system has a valid DoD root CA installed with the following
command:

    $ sudo openssl x509 -text -in /etc/sssd/pki/sssd_auth_ca_db.pem

    Certificate:
       Data:
          Version: 3 (0x2)
          Serial Number: 1 (0x1)
          Signature Algorithm: sha256WithRSAEncryption
          Issuer: C = US, O = U.S. Government, OU = DoD, OU = PKI, CN = DoD
Root CA 3
          Validity
             Not Before: Mar 20 18:46:41 2012 GMT
             Not After   : Dec 30 18:46:41 2029 GMT
          Subject: C = US, O = U.S. Government, OU = DoD, OU = PKI, CN = DoD
Root CA 3
          Subject Public Key Info:
             Public Key Algorithm: rsaEncryption

    If the root ca file is not a DoD-issued certificate with a valid date and
installed in the /etc/sssd/pki/sssd_auth_ca_db.pem location, this is a finding.

```

Updated:
```
Verify RHEL 8 for PKI-based authentication has valid certificates by constructing a certification path (which includes status information) to an accepted trust anchor.

Note: If the System Administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

Check that the system has a valid DoD root CA installed with the following command:

$ sudo openssl x509 -text -in /etc/sssd/pki/sssd_auth_ca_db.pem

Certificate:
   Data:
      Version: 3 (0x2)
      Serial Number: 1 (0x1)
      Signature Algorithm: sha256WithRSAEncryption
      Issuer: C = US, O = U.S. Government, OU = DoD, OU = PKI, CN = DoD Root CA 3
      Validity
         Not Before: Mar 20 18:46:41 2012 GMT
         Not After   : Dec 30 18:46:41 2029 GMT
      Subject: C = US, O = U.S. Government, OU = DoD, OU = PKI, CN = DoD Root CA 3
      Subject Public Key Info:
         Public Key Algorithm: rsaEncryption

If the root ca file is not a DoD-issued certificate with a valid date and installed in the /etc/sssd/pki/sssd_auth_ca_db.pem location, this is a finding.

```
---
SV-230237:
Old: 
```
Verify that the pam_unix.so module is configured to use sha512.

    Check that the pam_unix.so module is configured to use sha512 in
/etc/pam.d/password-auth with the following command:

    $ sudo grep password /etc/pam.d/password-auth | grep pam_unix

    password sufficient pam_unix.so sha512 rounds=5000

    If "sha512" is missing, or is commented out, this is a finding.

```

Updated:
```
Verify that the pam_unix.so module is configured to use sha512.

Check that the pam_unix.so module is configured to use sha512 in /etc/pam.d/password-auth with the following command:

$ sudo grep password /etc/pam.d/password-auth | grep pam_unix

password sufficient pam_unix.so sha512

If "sha512" is missing, or is commented out, this is a finding.

```
---
SV-230243:
Old: 
```
Verify that all world-writable directories have the sticky bit set.

    Check to see that all world-writable directories have the sticky bit set by
running the following command:

    $ sudo find / -type d \( -perm -0002 -a ! -perm -1000 \) -print
2>/dev/null

    drwxrwxrwxt 7 root root 4096 Jul 26 11:19 /tmp

    If any of the returned directories are world-writable and do not have the
sticky bit set, this is a finding.

```

Updated:
```
Verify that all world-writable directories have the sticky bit set.

Check to see that all world-writable directories have the sticky bit set by running the following command:

$ sudo find / -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null

drwxrwxrwt 7 root root 4096 Jul 26 11:19 /tmp

If any of the returned directories are world-writable and do not have the sticky bit set, this is a finding.

```
---
SV-230252:
Old: 
```
Verify the SSH server is configured to use only ciphers employing FIPS
140-2-approved algorithms with the following command:

    $ sudo grep -i ciphers /etc/crypto-policies/back-ends/opensshserver.config

    CRYPTO_POLICY='-oCiphers=aes256-ctr,aes192-ctr,aes128-ctr'

    If the cipher entries in the "opensshserver.config" file have any ciphers
other than "aes256-ctr,aes192-ctr,aes128-ctr", the order differs from the
example above, they are missing, or commented out, this is a finding.

```

Updated:
```
Verify the SSH server is configured to use only ciphers employing FIPS 140-2-approved algorithms with the following command:

     $ sudo grep -i ciphers /etc/crypto-policies/back-ends/opensshserver.config

     CRYPTO_POLICY='-oCiphers=aes256-ctr,aes192-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com'

If the cipher entries in the "opensshserver.config" file have any ciphers other than shown here, the order differs from the example above, or they are missing or commented out, this is a finding.

```
---
SV-230255:
Old: 
```
Verify the OpenSSL library is configured to use only DoD-approved TLS
encryption:

    $ sudo grep -i  MinProtocol /etc/crypto-policies/back-ends/opensslcnf.config

    MinProtocol = TLSv1.2

    If the "MinProtocol" is set to anything older than "TLSv1.2", this is a
finding.

```

Updated:
```
Verify the OpenSSL library is configured to use only DoD-approved TLS encryption:

For versions prior to crypto-policies-20210617-1.gitc776d3e.el8.noarch:

$ sudo grep -i  MinProtocol /etc/crypto-policies/back-ends/opensslcnf.config

MinProtocol = TLSv1.2

If the "MinProtocol" is set to anything older than "TLSv1.2", this is a finding.

For version crypto-policies-20210617-1.gitc776d3e.el8.noarch and newer:

$ sudo grep -i  MinProtocol /etc/crypto-policies/back-ends/opensslcnf.config

TLS.MinProtocol = TLSv1.2
DTLS.MinProtocol = DTLSv1.2

If the "TLS.MinProtocol" is set to anything older than "TLSv1.2" or the "DTLS.MinProtocol" is set to anything older than DTLSv1.2, this is a finding.

```
---
SV-230257:
Old: 
```
Verify the system commands contained in the following directories have mode
"0755" or less permissive with the following command:

    $ sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin
-perm /0022 -exec ls -l {} \;

    If any system commands are found to be group-writable or world-writable,
this is a finding.

```

Updated:
```
Verify the system commands contained in the following directories have mode "755" or less permissive with the following command:

$ sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -exec ls -l {} \;

If any system commands are found to be group-writable or world-writable, this is a finding.

```
---
SV-230259:
Old: 
```
Verify the system commands contained in the following directories are
group-owned by "root" with the following command:

    $ sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin
! -group root -exec ls -l {} \;

    If any system commands are returned and is not owned by a required system
account, this is a finding.

```

Updated:
```
Verify the system commands contained in the following directories are group-owned by "root", or a required system account, with the following command:

$ sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -exec ls -l {} \;

If any system commands are returned and is not group-owned by a required system account, this is a finding.

```
---
SV-230260:
Old: 
```
Verify the system-wide shared library files contained in the following
directories have mode "0755" or less permissive with the following command:

    $ sudo find -L /lib /lib64 /usr/lib /usr/lib64 -perm /0022 -type f -exec ls
-l {} \;

    If any system-wide shared library file is found to be group-writable or
world-writable, this is a finding.

```

Updated:
```
Verify the system-wide shared library files contained in the following directories have mode "755" or less permissive with the following command:

$ sudo find -L /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type f -exec ls -l {} \;

If any system-wide shared library file is found to be group-writable or world-writable, this is a finding.

```
---
SV-230263:
Old: 
```
Verify the operating system routinely checks the baseline configuration for
unauthorized changes and notifies the system administrator when anomalies in
the operation of any security functions are discovered.

    Check to see if AIDE is installed on the system with the following command:

    $ sudo yum list installed aide

    If AIDE is not installed, ask the System Administrator how file integrity
checks are performed on the system.

    Check that RHEL 8 routinely executes a file integrity scan for changes to
the system baseline. The command used in the example will use a daily
occurrence.

    Check the cron directories for scripts controlling the execution and
notification of results of the file integrity application. For example, if AIDE
is installed on the system, use the following commands:

    $ sudo ls -al /etc/cron.* | grep aide

    -rwxr-xr-x 1 root root 29 Nov 22 2015 aide

    $ sudo grep aide /etc/crontab /var/spool/cron/root

    /etc/crontab: 30 04 * * * root usr/sbin/aide
    /var/spool/cron/root: 30 04 * * * root usr/sbin/aide

    $ sudo more /etc/cron.daily/aide

    #!/bin/bash
    /usr/sbin/aide --check | /bin/mail -s "$HOSTNAME - Daily aide integrity
check run" root@sysname.mil

    If the file integrity application does not exist, or a script file
controlling the execution of the file integrity application does not exist, or
the file integrity application does not notify designated personnel of changes,
this is a finding.

```

Updated:
```
Verify the operating system routinely checks the baseline configuration for unauthorized changes and notifies the system administrator when anomalies in the operation of any security functions are discovered.

Check that RHEL 8 routinely executes a file integrity scan for changes to the system baseline. The command used in the example will use a daily occurrence.

Check the cron directories for scripts controlling the execution and notification of results of the file integrity application. For example, if AIDE is installed on the system, use the following commands:

     $ sudo ls -al /etc/cron.* | grep aide

     -rwxr-xr-x 1 root root 29 Nov 22 2015 aide

     $ sudo grep aide /etc/crontab /var/spool/cron/root

     /etc/crontab: 30 04 * * * root /usr/sbin/aide
     /var/spool/cron/root: 30 04 * * * root /usr/sbin/aide

     $ sudo more /etc/cron.daily/aide

     #!/bin/bash
     /usr/sbin/aide --check | /bin/mail -s "$HOSTNAME - Daily AIDE integrity check run" root@example_server_name.mil

If the file integrity application does not exist, or a script file controlling the execution of the file integrity application does not exist, or the file integrity application does not notify designated personnel of changes, this is a finding.

```
---
SV-230264:
Old: 
```
Verify the operating system prevents the installation of patches, service
packs, device drivers, or operating system components from a repository without
verification that they have been digitally signed using a certificate that is
recognized and approved by the organization.

    Check that YUM verifies the signature of packages from a repository prior
to install with the following command:

    $ sudo egrep '^\[.*\]|gpgcheck' /etc/yum.repos.d/*.repo

    /etc/yum.repos.d/appstream.repo:[appstream]
    /etc/yum.repos.d/appstream.repo:gpgcheck=1
    /etc/yum.repos.d/baseos.repo:[baseos]
    /etc/yum.repos.d/baseos.repo:gpgcheck=1

    If "gpgcheck" is not set to "1", or if options are missing or commented
out, ask the System Administrator how the certificates for patches and other
operating system components are verified.

    If there is no process to validate certificates that is approved by the
organization, this is a finding.

```

Updated:
```
Verify the operating system prevents the installation of patches, service packs, device drivers, or operating system components from a repository without verification that they have been digitally signed using a certificate that is recognized and approved by the organization.

Check that YUM verifies the signature of packages from a repository prior to install with the following command:

     $ sudo grep -E '^\[.*\]|gpgcheck' /etc/yum.repos.d/*.repo

     /etc/yum.repos.d/appstream.repo:[appstream]
     /etc/yum.repos.d/appstream.repo:gpgcheck=1
     /etc/yum.repos.d/baseos.repo:[baseos]
     /etc/yum.repos.d/baseos.repo:gpgcheck=1

If "gpgcheck" is not set to "1", or if options are missing or commented out, ask the System Administrator how the certificates for patches and other operating system components are verified.

If there is no process to validate certificates that is approved by the organization, this is a finding.

```
---
SV-230266:
Old: 
```
Verify the operating system is configured to disable kernel image loading
with the following commands:

    Check the status of the kernel.kexec_load_disabled kernel parameter

    $ sudo sysctl kernel.kexec_load_disabled

    kernel.kexec_load_disabled = 1

    If "kernel.kexec_load_disabled" is not set to "1" or is missing, this
is a finding.

    Check that the configuration files are present to enable this kernel
parameter

    $ sudo grep -r kernel.kexec_load_disabled /etc/sysctl.conf
/etc/sysctl.d/*.conf

    /etc/sysctl.d/99-sysctl.conf:kernel.kexec_load_disabled = 1

    If "kernel.kexec_load_disabled" is not set to "1", is missing or
commented out, this is a finding.

```

Updated:
```
Verify the operating system is configured to disable kernel image loading with the following commands:

Check the status of the kernel.kexec_load_disabled kernel parameter.

$ sudo sysctl kernel.kexec_load_disabled

kernel.kexec_load_disabled = 1

If "kernel.kexec_load_disabled" is not set to "1" or is missing, this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo grep -r kernel.kexec_load_disabled /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf:kernel.kexec_load_disabled = 1

If "kernel.kexec_load_disabled" is not set to "1", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-230267:
Old: 
```
Verify the operating system is configured to enable DAC on symlinks with
the following commands:

    Check the status of the fs.protected_symlinks kernel parameter

    $ sudo sysctl fs.protected_symlinks

    fs.protected_symlinks = 1

    If "fs.protected_symlinks" is not set to "1" or is missing, this is a
finding.

    Check that the configuration files are present to enable this kernel
parameter

    $ sudo grep -r fs.protected_symlinks /etc/sysctl.conf /etc/sysctl.d/*.conf

    /etc/sysctl.d/99-sysctl.conf:fs.protected_symlinks = 1

    If "fs.protected_symlinks" is not set to "1", is missing or commented
out, this is a finding.

```

Updated:
```
Verify the operating system is configured to enable DAC on symlinks with the following commands:

Check the status of the fs.protected_symlinks kernel parameter.

$ sudo sysctl fs.protected_symlinks

fs.protected_symlinks = 1

If "fs.protected_symlinks" is not set to "1" or is missing, this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo grep -r fs.protected_symlinks /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf:fs.protected_symlinks = 1

If "fs.protected_symlinks" is not set to "1", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-230268:
Old: 
```
Verify the operating system is configured to enable DAC on hardlinks with
the following commands:

    Check the status of the fs.protected_hardlinks kernel parameter.

    $ sudo sysctl fs.protected_hardlinks

    fs.protected_hardlinks = 1

    If "fs.protected_hardlinks" is not set to "1" or is missing, this is a
finding.

    Check that the configuration files are present to enable this kernel
parameter.

    $ sudo grep -r fs.protected_hardlinks /etc/sysctl.conf /etc/sysctl.d/*.conf

    /etc/sysctl.d/99-sysctl.conf:fs.protected_hardlinks = 1

    If "fs.protected_hardlinks" is not set to "1", is missing or commented
out, this is a finding.

```

Updated:
```
Verify the operating system is configured to enable DAC on hardlinks with the following commands:

Check the status of the fs.protected_hardlinks kernel parameter.

$ sudo sysctl fs.protected_hardlinks

fs.protected_hardlinks = 1

If "fs.protected_hardlinks" is not set to "1" or is missing, this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo grep -r fs.protected_hardlinks /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf:fs.protected_hardlinks = 1

If "fs.protected_hardlinks" is not set to "1", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-230269:
Old: 
```
Verify the operating system is configured to restrict access to the kernel
message buffer with the following commands:

    Check the status of the kernel.dmesg_restrict kernel parameter.

    $ sudo sysctl kernel.dmesg_restrict

    kernel.dmesg_restrict = 1

    If "kernel.dmesg_restrict" is not set to "1" or is missing, this is a
finding.

    Check that the configuration files are present to enable this kernel
parameter.

    $ sudo grep -r kernel.dmesg_restrict /etc/sysctl.conf /etc/sysctl.d/*.conf

    /etc/sysctl.d/99-sysctl.conf:kernel.dmesg_restrict = 1

    If "kernel.dmesg_restrict" is not set to "1", is missing or commented
out, this is a finding.

```

Updated:
```
Verify the operating system is configured to restrict access to the kernel message buffer with the following commands:

Check the status of the kernel.dmesg_restrict kernel parameter.

$ sudo sysctl kernel.dmesg_restrict

kernel.dmesg_restrict = 1

If "kernel.dmesg_restrict" is not set to "1" or is missing, this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo grep -r kernel.dmesg_restrict /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf:kernel.dmesg_restrict = 1

If "kernel.dmesg_restrict" is not set to "1", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-230270:
Old: 
```
Verify the operating system is configured to prevent kernel profiling by
unprivileged users with the following commands:

    Check the status of the kernel.perf_event_paranoid kernel parameter.

    $ sudo sysctl kernel.perf_event_paranoid

    kernel.perf_event_paranoid = 2

    If "kernel.perf_event_paranoid" is not set to "2" or is missing, this
is a finding.

    Check that the configuration files are present to enable this kernel
parameter.

    $ sudo grep -r kernel.perf_event_paranoid /etc/sysctl.conf
/etc/sysctl.d/*.conf

    /etc/sysctl.d/99-sysctl.conf:kernel.perf_event_paranoid = 2

    If "kernel.perf_event_paranoid" is not set to "2", is missing or
commented out, this is a finding.

```

Updated:
```
Verify the operating system is configured to prevent kernel profiling by unprivileged users with the following commands:

Check the status of the kernel.perf_event_paranoid kernel parameter.

$ sudo sysctl kernel.perf_event_paranoid

kernel.perf_event_paranoid = 2

If "kernel.perf_event_paranoid" is not set to "2" or is missing, this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo grep -r kernel.perf_event_paranoid /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf:kernel.perf_event_paranoid = 2

If "kernel.perf_event_paranoid" is not set to "2", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-230280:
Old: 
```
Verify RHEL 8 implements ASLR with the following command:

    $ sudo sysctl kernel.randomize_va_space

    kernel.randomize_va_space = 2

    If nothing is returned, verify the kernel parameter "randomize_va_space"
is set to "2" with the following command:

    $ sudo cat /proc/sys/kernel/randomize_va_space

    2

    If "kernel.randomize_va_space" is not set to "2", this is a finding.

```

Updated:
```
Verify RHEL 8 implements ASLR with the following command:

$ sudo sysctl kernel.randomize_va_space

kernel.randomize_va_space = 2

If "kernel.randomize_va_space" is not set to "2", this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo grep -r kernel.randomize_va_space /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf:kernel.randomize_va_space = 2

If "kernel.randomize_va_space" is not set to "2", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-230288:
Old: 
```
Verify the SSH daemon performs strict mode checking of home directory
configuration files with the following command:

    $ sudo grep -i strictmodes /etc/ssh/sshd_config

    StrictModes yes

    If "StrictModes" is set to "no", is missing, or the returned line is
commented out, this is a finding.

```

Updated:
```
Verify the SSH daemon performs strict mode checking of home directory configuration files with the following command:

$ sudo grep -ir strictmodes /etc/ssh/sshd_config*

StrictModes yes

If "StrictModes" is set to "no", is missing, or the returned line is commented out, this is a finding.
If conflicting results are returned, this is a finding.

```
---
SV-230290:
Old: 
```
Verify the SSH daemon does not allow authentication using known host’s
authentication with the following command:

    $ sudo grep -i IgnoreUserKnownHosts /etc/ssh/sshd_config

    IgnoreUserKnownHosts yes

    If the value is returned as "no", the returned line is commented out, or
no output is returned, this is a finding.

```

Updated:
```
Verify the SSH daemon does not allow authentication using known host’s authentication with the following command:

$ sudo grep -ir IgnoreUserKnownHosts /etc/ssh/sshd_config*

IgnoreUserKnownHosts yes

If the value is returned as "no", the returned line is commented out, or no output is returned, this is a finding.
If conflicting results are returned, this is a finding.

```
---
SV-230291:
Old: 
```
Verify the SSH daemon does not allow Kerberos authentication with the
following command:

    $ sudo grep -i KerberosAuthentication  /etc/ssh/sshd_config

    KerberosAuthentication no

    If the value is returned as "yes", the returned line is commented out, no
output is returned, or has not been documented with the ISSO, this is a finding.

```

Updated:
```
Verify the SSH daemon does not allow Kerberos authentication with the following command:

$ sudo grep -ir KerberosAuthentication  /etc/ssh/sshd_config*

KerberosAuthentication no

If the value is returned as "yes", the returned line is commented out, no output is returned, or has not been documented with the ISSO, this is a finding.
If conflicting results are returned, this is a finding.

```
---
SV-230292:
Old: 
```
Verify that a separate file system/partition has been created for "/var".

    Check that a file system/partition has been created for "/var" with the
following command:

    $ sudo grep /var /etc/fstab

    UUID=c274f65f /var xfs noatime,nobarrier 1 2

    If a separate entry for "/var" is not in use, this is a finding.

```

Updated:
```
Verify that a separate file system has been created for "/var".

Check that a file system has been created for "/var" with the following command:

     $ sudo grep /var /etc/fstab

     /dev/mapper/...   /var   xfs   defaults,nodev 0 0

If a separate entry for "/var" is not in use, this is a finding.

```
---
SV-230293:
Old: 
```
Verify that a separate file system/partition has been created for
"/var/log".

    Check that a file system/partition has been created for "/var/log" with
the following command:

    $ sudo grep /var/log /etc/fstab

    UUID=c274f65f /var/log xfs noatime,nobarrier 1 2

    If a separate entry for "/var/log" is not in use, this is a finding.

```

Updated:
```
Verify that a separate file system has been created for "/var/log".

Check that a file system has been created for "/var/log" with the following command:

     $ sudo grep /var/log /etc/fstab

     /dev/mapper/...   /var/log   xfs   defaults,nodev,noexec,nosuid 0 0

If a separate entry for "/var/log" is not in use, this is a finding.

```
---
SV-230296:
Old: 
```
Verify remote access using SSH prevents users from logging on directly as
"root".

    Check that SSH prevents users from logging on directly as "root" with the
following command:

    $ sudo grep -i PermitRootLogin /etc/ssh/sshd_config

    PermitRootLogin no

    If the "PermitRootLogin" keyword is set to "yes", is missing, or is
commented out, this is a finding.

```

Updated:
```
Verify remote access using SSH prevents users from logging on directly as "root".

Check that SSH prevents users from logging on directly as "root" with the following command:

$ sudo grep -ir PermitRootLogin /etc/ssh/sshd_config*

PermitRootLogin no

If the "PermitRootLogin" keyword is set to "yes", is missing, or is commented out, this is a finding.
If conflicting results are returned, this is a finding.

```
---
SV-230311:
Old: 
```
Verify RHEL 8 disables storing core dumps with the following commands:

    $ sudo sysctl kernel.core_pattern

    kernel.core_pattern = |/bin/false

    If the returned line does not have a value of "|/bin/false", or a line is
not returned and the need for core dumps is not documented with the Information
System Security Officer (ISSO) as an operational requirement, this is a finding.

```

Updated:
```
Verify RHEL 8 disables storing core dumps with the following commands:

$ sudo sysctl kernel.core_pattern

kernel.core_pattern = |/bin/false

If the returned line does not have a value of "|/bin/false", or a line is not returned and the need for core dumps is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo grep -r kernel.core_pattern /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf:kernel.core_pattern = |/bin/false

If "kernel.core_pattern" is not set to "|/bin/false", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-230312:
Old: 
```
Verify RHEL 8 is not configured to acquire, save, or process core dumps
with the following command:

    $ sudo systemctl status systemd-coredump.socket

    systemd-coredump.socket
    Loaded: masked (Reason: Unit ctrl-alt-del.target is masked.)
    Active: inactive (dead)

    If the "systemd-coredump.socket" is loaded and not masked and the need
for core dumps is not documented with the Information System Security Officer
(ISSO) as an operational requirement, this is a finding.

```

Updated:
```
Verify RHEL 8 is not configured to acquire, save, or process core dumps with the following command:

$ sudo systemctl status systemd-coredump.socket

systemd-coredump.socket
Loaded: masked (Reason: Unit systemd-coredump.socket is masked.)
Active: inactive (dead)

If the "systemd-coredump.socket" is loaded and not masked and the need for core dumps is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

```
---
SV-230317:
Old: 
```
Verify that all local interactive user initialization file executable
search path statements do not contain statements that will reference a working
directory other than user home directories with the following commands:

    $ sudo grep -i path /home/*/.*


/home/[localinteractiveuser]/.bash_profile:PATH=$PATH:$HOME/.local/bin:$HOME/bin
    /home/[localinteractiveuser]/.bash_profile:export PATH

    If any local interactive user initialization files have executable search
path statements that include directories outside of their home directory and is
not documented with the ISSO as an operational requirement, this is a finding.

```

Updated:
```
Verify that all local interactive user initialization file executable search path statements do not contain statements that will reference a working directory other than user home directories with the following commands:

$ sudo grep -i path= /home/*/.*

/home/[localinteractiveuser]/.bash_profile:PATH=$PATH:$HOME/.local/bin:$HOME/bin

If any local interactive user initialization files have executable search path statements that include directories outside of their home directory and is not documented with the ISSO as an operational requirement, this is a finding.

```
---
SV-230325:
Old: 
```
Verify that all local initialization files have a mode of "0740" or less
permissive with the following command:

    Note: The example will be for the "smithj" user, who has a home directory
of "/home/smithj".

    $ sudo ls -al /home/smithj/.[^.]* | more

    -rwxr-xr-x 1 smithj users 896 Mar 10 2011 .profile
    -rwxr-xr-x 1 smithj users 497 Jan 6 2007 .login
    -rwxr-xr-x 1 smithj users 886 Jan 6 2007 .something

    If any local initialization files have a mode more permissive than
"0740", this is a finding.

```

Updated:
```
Verify that all local initialization files have a mode of "0740" or less permissive with the following command:

Note: The example will be for the "smithj" user, who has a home directory of "/home/smithj".

     $ sudo ls -al /home/smithj/.[^.]* | more

     -rw-------. 1 smithj users 2984 Apr 27 19:02 .bash_history
     -rw-r--r--. 1 smithj users   18 Aug 21  2019 .bash_logout
     -rw-r--r--. 1 smithj users  193 Aug 21  2019 .bash_profile

If any local initialization files have a mode more permissive than "0740", this is a finding.

```
---
SV-230328:
Old: 
```
Verify that a separate file system/partition has been created for
non-privileged local interactive user home directories.

    Check the home directory assignment for all non-privileged users, users
with a User Identifier (UID) greater than 1000, on the system with the
following command:

    $ sudo awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' /etc/passwd

    adamsj 1001 /home/adamsj
    jacksonm 1002 /home/jacksonm
    smithj 1003 /home/smithj

    The output of the command will give the directory/partition that contains
the home directories for the non-privileged users on the system (in this
example, "/home") and users’ shell. All accounts with a valid shell (such as
/bin/bash) are considered interactive users.

    Check that a file system/partition has been created for the non-privileged
interactive users with the following command:

    Note: The partition of "/home" is used in the example.

    $ sudo grep /home /etc/fstab

    UUID=333ada18 /home ext4 noatime,nobarrier,nodev 1 2

    If a separate entry for the file system/partition containing the
non-privileged interactive user home directories does not exist, this is a
finding.

```

Updated:
```
Verify that a separate file system has been created for non-privileged local interactive user home directories.

Check the home directory assignment for all non-privileged users, users with a User Identifier (UID) greater than 1000, on the system with the following command:

     $ sudo awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' /etc/passwd

     doej 1001 /home/doej 
     publicj 1002 /home/publicj 
     smithj 1003 /home/smithj

The output of the command will give the directory/partition that contains the home directories for the non-privileged users on the system (in this example, "/home") and users’ shell. All accounts with a valid shell (such as /bin/bash) are considered interactive users.

Check that a file system/partition has been created for the nonprivileged interactive users with the following command:

Note: The partition of "/home" is used in the example.

     $ sudo grep /home /etc/fstab

     /dev/mapper/...   /home   xfs   defaults,noexec,nosuid,nodev 0 0

If a separate entry for the file system/partition containing the nonprivileged interactive user home directories does not exist, this is a finding.

```
---
SV-230330:
Old: 
```
Verify that unattended or automatic logon via ssh is disabled with the
following command:

    $ sudo grep -i PermitUserEnvironment /etc/ssh/sshd_config

    PermitUserEnvironment no

    If "PermitUserEnvironment" is set to "yes", is missing completely, or
is commented out, this is a finding.

```

Updated:
```
Verify that unattended or automatic logon via ssh is disabled with the following command:

$ sudo grep -ir PermitUserEnvironment /etc/ssh/sshd_config*

PermitUserEnvironment no

If "PermitUserEnvironment" is set to "yes", is missing completely, or is commented out, this is a finding.
If conflicting results are returned, this is a finding.

```
---
SV-230348:
Old: 
```
Verify the operating system enables the user to initiate a session lock
with the following command:

    $ sudo grep -i lock-command /etc/tmux.conf

    set -g lock-command vlock

    If the "lock-command" is not set in the global settings to call
"vlock", this is a finding.

```

Updated:
```
Verify the operating system enables the user to manually initiate a session lock with the following command:

     $ sudo grep -Ei 'lock-command|lock-session' /etc/tmux.conf

     set -g lock-command vlock
     bind X lock-session

If the "lock-command" is not set and "lock-session" is not bound to a specific keyboard key in the global settings, this is a finding.

```
---
SV-230349:
Old: 
```
Verify the operating system shell initialization file is configured to
start each shell with the tmux terminal multiplexer with the following command:

    $ sudo grep -i tmux /etc/bashrc

    [ -n "$PS1" -a -z "$TMUX" ] && exec tmux

    If "tmux" is not configured as the example above, is commented out, or
missing from the "/etc/bashrc" initialization file, this is a finding.

```

Updated:
```
Verify the operating system shell initialization file is configured to start each shell with the tmux terminal multiplexer with the following commands:

Determine if tmux is currently running:
     $ sudo ps all | grep tmux | grep -v grep

If the command does not produce output, this is a finding.
 
Determine the location of the tmux script:
     $ sudo grep -r tmux /etc/bashrc /etc/profile.d

     /etc/profile.d/tmux.sh:  case "$name" in (sshd|login) tmux ;; esac

Review the tmux script by using the following example:
     $ sudo cat /etc/profile.d/tmux.sh

if [ "$PS1" ]; then
parent=$(ps -o ppid= -p $$)
name=$(ps -o comm= -p $parent)
case "$name" in (sshd|login) tmux ;; esac
fi

If "tmux" is not configured as the example above, is commented out, or is missing, this is a finding.

```
---
SV-230355:
Old: 
```
Verify the certificate of the user or group is mapped to the corresponding
user or group in the "sssd.conf" file with the following command:

    $ sudo cat /etc/sssd/sssd.conf

    [sssd]
    config_file_version = 2
    services = pam, sudo, ssh
    domains = testing.test

    [pam]
    pam_cert_auth = True

    [domain/testing.test]
    id_provider = ldap

    [certmap/testing.test/rule_name]
    matchrule =<SAN>.*EDIPI@mil
    maprule = (userCertificate;binary={cert!bin})
    domains = testing.test

    If the certmap section does not exist, ask the System Administrator to
indicate how certificates are mapped to accounts.  If there is no evidence of
certificate mapping, this is a finding.

```

Updated:
```
Verify the certificate of the user or group is mapped to the corresponding user or group in the "sssd.conf" file with the following command:

Note: If the System Administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

$ sudo cat /etc/sssd/sssd.conf

[sssd]
config_file_version = 2
services = pam, sudo, ssh
domains = testing.test

[pam]
pam_cert_auth = True

[domain/testing.test]
id_provider = ldap

[certmap/testing.test/rule_name]
matchrule =<SAN>.*EDIPI@mil
maprule = (userCertificate;binary={cert!bin})
domains = testing.test

If the certmap section does not exist, ask the System Administrator to indicate how certificates are mapped to accounts. If there is no evidence of certificate mapping, this is a finding.

```
---
SV-230357:
Old: 
```
Verify the value for "ucredit" in "/etc/security/pwquality.conf" with
the following command:

    $ sudo grep ucredit /etc/security/pwquality.conf

    ucredit = -1

    If the value of "ucredit" is a positive number or is commented out, this
is a finding.

```

Updated:
```
Verify the value for "ucredit" with the following command:

$ sudo grep -r ucredit /etc/security/pwquality.conf*

/etc/security/pwquality.conf:ucredit = -1

If the value of "ucredit" is a positive number or is commented out, this is a finding.
If conflicting results are returned, this is a finding.

```
---
SV-230358:
Old: 
```
Verify the value for "lcredit" in "/etc/security/pwquality.conf" with
the following command:

    $ sudo grep lcredit /etc/security/pwquality.conf

    lcredit = -1

    If the value of "lcredit" is a positive number or is commented out, this
is a finding.

```

Updated:
```
Verify the value for "lcredit" with the following command:

$ sudo grep -r lcredit /etc/security/pwquality.conf*

/etc/security/pwquality.conf:lcredit = -1

If the value of "lcredit" is a positive number or is commented out, this is a finding.
If conflicting results are returned, this is a finding.

```
---
SV-230359:
Old: 
```
Verify the value for "dcredit" in "/etc/security/pwquality.conf" with
the following command:

    $ sudo grep dcredit /etc/security/pwquality.conf

    dcredit = -1

    If the value of "dcredit" is a positive number or is commented out, this
is a finding.

```

Updated:
```
Verify the value for "dcredit" with the following command:

$ sudo grep -r dcredit /etc/security/pwquality.conf*

/etc/security/pwquality.conf:dcredit = -1

If the value of "dcredit" is a positive number or is commented out, this is a finding.
If conflicting results are returned, this is a finding.

```
---
SV-230360:
Old: 
```
Check for the value of the "maxclassrepeat" option in
"/etc/security/pwquality.conf" with the following command:

    $ sudo grep maxclassrepeat /etc/security/pwquality.conf

    maxclassrepeat = 4

    If the value of "maxclassrepeat" is set to more than "4" or is
commented out, this is a finding.

```

Updated:
```
Check for the value of the "maxclassrepeat" option with the following command:

$ sudo grep -r maxclassrepeat /etc/security/pwquality.conf*

/etc/security/pwquality.conf:maxclassrepeat = 4

If the value of "maxclassrepeat" is set to "0", more than "4" or is commented out, this is a finding.
If conflicting results are returned, this is a finding.

```
---
SV-230361:
Old: 
```
Check for the value of the "maxrepeat" option in
"/etc/security/pwquality.conf" with the following command:

    $ sudo grep maxrepeat /etc/security/pwquality.conf

    maxrepeat = 3

    If the value of "maxrepeat" is set to more than "3" or is commented
out, this is a finding.

```

Updated:
```
Check for the value of the "maxrepeat" option with the following command:

$ sudo grep -r maxrepeat /etc/security/pwquality.conf*

/etc/security/pwquality.conf:maxrepeat = 3

If the value of "maxrepeat" is set to more than "3" or is commented out, this is a finding.
If conflicting results are returned, this is a finding.

```
---
SV-230362:
Old: 
```
Verify the value of the "minclass" option in
"/etc/security/pwquality.conf" with the following command:

    $ sudo grep minclass /etc/security/pwquality.conf
    minclass = 4

    If the value of "minclass" is set to less than "4" or is commented out,
this is a finding.

```

Updated:
```
Verify the value of the "minclass" option with the following command:

$ sudo grep -r minclass /etc/security/pwquality.conf*

/etc/security/pwquality.conf:minclass = 4

If the value of "minclass" is set to less than "4" or is commented out, this is a finding.
If conflicting results are returned, this is a finding.

```
---
SV-230363:
Old: 
```
Verify the value of the "difok" option in
"/etc/security/pwquality.conf" with the following command:

    $ sudo grep difok /etc/security/pwquality.conf

    difok = 8

    If the value of "difok" is set to less than "8" or is commented out,
this is a finding.

```

Updated:
```
Verify the value of the "difok" option with the following command:

$ sudo grep -r difok /etc/security/pwquality.conf*

/etc/security/pwquality.conf:difok = 8

If the value of "difok" is set to less than "8" or is commented out, this is a finding.
If conflicting results are returned, this is a finding.

```
---
SV-230368:
Old: 
```
Verify the operating system prohibits password reuse for a minimum of five
generations.

    Check for the value of the "remember" argument in
"/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" with the following
command:

    $ sudo grep -i remember /etc/pam.d/system-auth /etc/pam.d/password-auth

    password required pam_pwhistory.so use_authtok remember=5 retry=3

    If the line containing "pam_pwhistory.so" does not have the "remember"
module argument set, is commented out, or the value of the "remember" module
argument is set to less than "5", this is a finding.

```

Updated:
```
Verify the operating system is configured in the password-auth file to prohibit password reuse for a minimum of five generations.

Check for the value of the "remember" argument in "/etc/pam.d/password-auth" with the following command:

     $ sudo grep -i remember /etc/pam.d/password-auth

     password requisite pam_pwhistory.so use_authtok remember=5 retry=3

If the line containing "pam_pwhistory.so" does not have the "remember" module argument set, is commented out, or the value of the "remember" module argument is set to less than "5", this is a finding.

```
---
SV-230369:
Old: 
```
Verify the operating system enforces a minimum 15-character password
length. The "minlen" option sets the minimum number of characters in a new
password.

    Check for the value of the "minlen" option in
"/etc/security/pwquality.conf" with the following command:

    $ sudo grep minlen /etc/security/pwquality.conf
    minlen = 15

    If the command does not return a "minlen" value of 15 or greater, this is
a finding.

```

Updated:
```
Verify the operating system enforces a minimum 15-character password length. The "minlen" option sets the minimum number of characters in a new password.

Check for the value of the "minlen" option with the following command:

$ sudo grep -r minlen /etc/security/pwquality.conf*

/etc/security/pwquality.conf:minlen = 15

If the command does not return a "minlen" value of 15 or greater, this is a finding.
If conflicting results are returned, this is a finding.

```
---
SV-230374:
Old: 
```
Verify emergency accounts have been provisioned with an expiration date of
72 hours.

    For every existing emergency account, run the following command to obtain
its account expiration information.

    $ sudo chage -l system_account_name

    Verify each of these accounts has an expiration date set within 72 hours.
    If any emergency accounts have no expiration date set or do not expire
within 72 hours, this is a finding.

```

Updated:
```
Verify temporary accounts have been provisioned with an expiration date of 72 hours.

For every existing temporary account, run the following command to obtain its account expiration information:

     $ sudo chage -l <temporary_account_name> | grep -i "account expires"

Verify each of these accounts has an expiration date set within 72 hours.
If any temporary accounts have no expiration date set or do not expire within 72 hours, this is a finding.

```
---
SV-230375:
Old: 
```
Verify the value for "ocredit" in "/etc/security/pwquality.conf" with
the following command:

    $ sudo grep ocredit /etc/security/pwquality.conf

    ocredit = -1

    If the value of "ocredit" is a positive number or is commented out, this
is a finding.

```

Updated:
```
Verify the value for "ocredit" with the following command:

$ sudo grep -r ocredit /etc/security/pwquality.conf*

/etc/security/pwquality.conf:ocredit = -1

If the value of "ocredit" is a positive number or is commented out, this is a finding.
If conflicting results are returned, this is a finding.

```
---
SV-230377:
Old: 
```
Verify RHEL 8 prevents the use of dictionary words for passwords.

    Determine if the field "dictcheck" is set in the
"/etc/security/pwquality.conf" or "/etc/pwquality.conf.d/*.conf" files with
the following command:

    $ sudo grep dictcheck /etc/security/pwquality.conf
/etc/pwquality.conf.d/*.conf

    dictcheck=1

    If the "dictcheck" parameter is not set to "1", or is commented out,
this is a finding.

```

Updated:
```
Verify RHEL 8 prevents the use of dictionary words for passwords.

Determine if the field "dictcheck" is set with the following command:

$ sudo grep -r dictcheck /etc/security/pwquality.conf*

/etc/security/pwquality.conf:dictcheck=1

If the "dictcheck" parameter is not set to "1", or is commented out, this is a finding.
If conflicting results are returned, this is a finding.

```
---
SV-230380:
Old: 
```
To verify that null passwords cannot be used, run the following command:

$ sudo grep -i permitemptypasswords /etc/ssh/sshd_config

PermitEmptyPasswords no

If "PermitEmptyPasswords" is set to "yes", this is a finding.

```

Updated:
```
To verify that null passwords cannot be used, run the following command:

$ sudo grep -ir permitemptypasswords /etc/ssh/sshd_config*

PermitEmptyPasswords no

If "PermitEmptyPasswords" is set to "yes", this is a finding.
If conflicting results are returned, this is a finding.

```
---
SV-230382:
Old: 
```
Verify SSH provides users with feedback on when account accesses last
occurred with the following command:

    $ sudo grep -i printlastlog /etc/ssh/sshd_config

    PrintLastLog yes

    If the "PrintLastLog" keyword is set to "no", is missing, or is
commented out, this is a finding.

```

Updated:
```
Verify SSH provides users with feedback on when account accesses last occurred with the following command:

$ sudo grep -ir printlastlog /etc/ssh/sshd_config*

PrintLastLog yes

If the "PrintLastLog" keyword is set to "no", is missing, or is commented out, this is a finding.
If conflicting results are returned, this is a finding.

```
---
SV-230384:
Old: 
```
Verify that the default umask for all local interactive users is "077".

    Identify the locations of all local interactive user home directories by
looking at the "/etc/passwd" file.

    Check all local interactive user initialization files for interactive users
with the following command:

    Note: The example is for a system that is configured to create users home
directories in the "/home" directory.

    # grep -i umask /home/*/.*

    If any local interactive user initialization files are found to have a
umask statement that has a value less restrictive than "077", this is a
finding.

```

Updated:
```
Verify that the default umask for all local interactive users is "077".

Identify the locations of all local interactive user home directories by looking at the "/etc/passwd" file.

Check all local interactive user initialization files for interactive users with the following command:

Note: The example is for a system that is configured to create users home directories in the "/home" directory.

$ sudo grep -ir ^umask /home | grep -v '.bash_history'

If any local interactive user initialization files are found to have a umask statement that has a value less restrictive than "077", this is a finding.

```
---
SV-230385:
Old: 
```
Verify that the umask default for installed shells is "077".

    Check for the value of the "UMASK" parameter in the "/etc/bashrc" and
"/etc/csh.cshrc" files with the following command:

    Note: If the value of the "UMASK" parameter is set to "000" in either
the "/etc/bashrc" or the "/etc/csh.cshrc" files, the Severity is raised to
a CAT I.

    # grep -i umask /etc/bashrc /etc/csh.cshrc

    /etc/bashrc:          umask 077
    /etc/bashrc:          umask 077
    /etc/csh.cshrc:      umask 077
    /etc/csh.cshrc:      umask 077

    If the value for the "UMASK" parameter is not "077", or the "UMASK"
parameter is missing or is commented out, this is a finding.

```

Updated:
```
Verify that the umask default for installed shells is "077".

Check for the value of the "UMASK" parameter in the "/etc/bashrc", "/etc/csh.cshrc" and "/etc/profile" files with the following command:

Note: If the value of the "UMASK" parameter is set to "000" in the "/etc/bashrc" the "/etc/csh.cshrc" or the "/etc/profile" files, the Severity is raised to a CAT I.

# grep -i umask /etc/bashrc /etc/csh.cshrc /etc/profile

/etc/bashrc:          umask 077
/etc/bashrc:          umask 077
/etc/csh.cshrc:      umask 077   
/etc/csh.cshrc:      umask 077
/etc/profile:      umask 077   
/etc/profile:      umask 077

If the value for the "UMASK" parameter is not "077", or the "UMASK" parameter is missing or is commented out, this is a finding.

```
---
SV-230413:
Old: 
```
Verify if RHEL 8 is configured to audit the execution of the
"lremovexattr" system call, by running the following command:

    $ sudo grep -w lremovexattr /etc/audit/audit.rules

    -a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
    -a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod

    -a always,exit -F arch=b32 -S lremovexattr -F auid=0 -k perm_mod
    -a always,exit -F arch=b64 -S lremovexattr -F auid=0 -k perm_mod

    If the command does not return all lines, or the lines are commented out,
this is a finding.

```

Updated:
```
Verify if RHEL 8 is configured to audit the execution of the "setxattr", "fsetxattr", "lsetxattr", "removexattr", "fremovexattr", and "lremovexattr" system calls by running the following command:

$ sudo grep xattr /etc/audit/audit.rules

-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod

-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod
-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod

If the command does not return an audit rule for "setxattr", "fsetxattr", "lsetxattr", "removexattr", "fremovexattr", and "lremovexattr" or any of the lines returned are commented out, this is a finding.

```
---
SV-230438:
Old: 
```
Verify RHEL 8 generates an audit record when successful/unsuccessful
attempts to use the "init_module" command by performing the following command
to check the file system rules in "/etc/audit/audit.rules":

    $ sudo grep -w "init_module" /etc/audit/audit.rules

    -a always,exit -F arch=b32 -S init_module -F auid>=1000 -F auid!=unset -k
module_chng
    -a always,exit -F arch=b64 -S init_module -F auid>=1000 -F auid!=unset -k
module_chng

    If the command does not return a line, or the line is commented out, this
is a finding.

```

Updated:
```
Verify RHEL 8 generates an audit record upon successful/unsuccessful attempts to use the "init_module" and "finit_module" system calls by using the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep init_module /etc/audit/audit.rules

-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng
-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng

If the command does not return an audit rule for "init_module" and "finit_module" or any of the lines returned are commented out, this is a finding.

```
---
SV-230439:
Old: 
```
Verify RHEL 8 generates an audit record when successful/unsuccessful
attempts to use the "rename" command by performing the following command to
check the file system rules in "/etc/audit/audit.rules":

    $ sudo grep -w "rename" /etc/audit/audit.rules

    -a always,exit -F arch=b32 -S rename -F auid>=1000 -F auid!=unset -k delete
    -a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=unset -k delete

    If the command does not return a line, or the line is commented out, this
is a finding.

```

Updated:
```
Verify RHEL 8 generates an audit record upon successful/unsuccessful attempts to use the "rename", "unlink", "rmdir", "renameat", and "unlinkat" system calls by using the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep 'rename\|unlink\|rmdir' /etc/audit/audit.rules

-a always,exit -F arch=b32 -S rename,unlink,rmdir,renameat,unlinkat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b64 -S rename,unlink,rmdir,renameat,unlinkat -F auid>=1000 -F auid!=unset -k delete

If the command does not return an audit rule for "rename", "unlink", "rmdir", "renameat", and "unlinkat" or any of the lines returned are commented out, this is a finding.

```
---
SV-230449:
Old: 
```
Verify RHEL 8 generates an audit record when successful/unsuccessful
attempts to use the "truncate" command by performing the following command to
check the file system rules in "/etc/audit/audit.rules":

    $ sudo grep -iw truncate /etc/audit/audit.rules

    -a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F
auid!=unset -k perm_access
    -a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F
auid!=unset -k perm_access

    -a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F
auid!=unset -k perm_access
    -a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F
auid!=unset -k perm_access

    If the command does not return all lines, or the lines are commented out,
this is a finding.

```

Updated:
```
Verify RHEL 8 generates an audit record upon successful/unsuccessful attempts to use the "truncate", "ftruncate", "creat", "open", "openat", and "open_by_handle_at" system calls by using the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep 'open\|truncate\|creat' /etc/audit/audit.rules

-a always,exit -F arch=b32 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access
-a always,exit -F arch=b64 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access

-a always,exit -F arch=b32 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access
-a always,exit -F arch=b64 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access

If the output does not produce rules containing "-F exit=-EPERM", this is a finding.
If the output does not produce rules containing "-F exit=-EACCES", this is a finding.
If the command does not return an audit rule for "truncate", "ftruncate", "creat", "open", "openat", and "open_by_handle_at" or any of the lines returned are commented out, this is a finding.

```
---
SV-230455:
Old: 
```
Verify RHEL 8 generates an audit record when successful/unsuccessful
attempts to use the "chown" command by performing the following command to
check the file system rules in "/etc/audit/audit.rules":

    $ sudo grep -w chown /etc/audit/audit.rules

    -a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=unset -k perm_mod
    -a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=unset -k perm_mod

    If the command does not return a line, or the line is commented out, this
is a finding.

```

Updated:
```
Verify RHEL 8 generates an audit record upon successful/unsuccessful attempts to use the "chown", "fchown", "fchownat" and "lchown" system calls by using the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep chown /etc/audit/audit.rules

-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod

If audit rules are not defined for "chown", "fchown", "fchownat", and "lchown" or any of the lines returned are commented out, this is a finding.

```
---
SV-230456:
Old: 
```
Verify RHEL 8 generates an audit record when successful/unsuccessful
attempts to use the "chmod" command by performing the following command to
check the file system rules in "/etc/audit/audit.rules":

    $ sudo grep -w chmod /etc/audit/audit.rules

    -a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=unset -k perm_mod
    -a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=unset -k perm_mod

    If the command does not return a line, or the line is commented out, this
is a finding.

```

Updated:
```
Verify RHEL 8 generates an audit record upon successful/unsuccessful attempts to use the "chmod", "fchmod", and "fchmodat" syscalls by using the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep chmod /etc/audit/audit.rules

-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod

If the command does not return an audit rule for "chmod", "fchmod", and "fchmodat", or any of the lines returned are commented out, this is a finding.

```
---
SV-230475:
Old: 
```
Verify that Advanced Intrusion Detection Environment (AIDE) is properly
configured to use cryptographic mechanisms to protect the integrity of audit
tools.

    If AIDE is not installed, ask the System Administrator how file integrity
checks are performed on the system.

    Check the selection lines to ensure AIDE is configured to add/check with
the following command:

    $ sudo egrep '(\/usr\/sbin\/(audit|au))' /etc/aide.conf

    /usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
    /usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
    /usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
    /usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
    /usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
    /usr/sbin/rsyslogd p+i+n+u+g+s+b+acl+xattrs+sha512
    /usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512

    If any of the audit tools listed above do not have an appropriate selection
line, ask the system administrator to indicate what cryptographic mechanisms
are being used to protect the integrity of the audit tools.  If there is no
evidence of integrity protection, this is a finding.

```

Updated:
```
Verify that Advanced Intrusion Detection Environment (AIDE) is properly configured to use cryptographic mechanisms to protect the integrity of audit tools.

If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system.

Check the selection lines to ensure AIDE is configured to add/check with the following command:

     $ sudo grep -E '(\/usr\/sbin\/(audit|au|rsys))' /etc/aide.conf

     /usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
     /usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
     /usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
     /usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
     /usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
     /usr/sbin/rsyslogd p+i+n+u+g+s+b+acl+xattrs+sha512
     /usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512

If any of the audit tools listed above do not have an appropriate selection line, ask the system administrator to indicate what cryptographic mechanisms are being used to protect the integrity of the audit tools. If there is no evidence of integrity protection, this is a finding.

```
---
SV-230476:
Old: 
```
Verify RHEL 8 allocates audit record storage capacity to store at least one
week of audit records when audit records are not immediately sent to a central
audit record storage facility.

    Determine to which partition the audit records are being written with the
following command:

    $ sudo grep log_file /etc/audit/auditd.conf
    log_file = /var/log/audit/audit.log

    Check the size of the partition to which audit records are written (with
the example being /var/log/audit/) with the following command:

    $ sudo df -h /var/log/audit/
    /dev/sda2 24G 10.4G 13.6G 43% /var/log/audit

    If the audit records are not written to a partition made specifically for
audit records (/var/log/audit is a separate partition), determine the amount of
space being used by other files in the partition with the following command:

    $ sudo du -sh [audit_partition]
    1.8G /var/log/audit

    If the audit record partition is not allocated for sufficient storage
capacity, this is a finding.

    Note: The partition size needed to capture a week of audit records is based
on the activity level of the system and the total storage capacity available.
Typically 10.0 GB of storage space for audit records should be sufficient.

```

Updated:
```
Verify RHEL 8 allocates audit record storage capacity to store at least one week of audit records when audit records are not immediately sent to a central audit record storage facility.

Determine to which partition the audit records are being written with the following command:

$ sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Check the size of the partition to which audit records are written (with the example being /var/log/audit/) with the following command:

$ sudo df -h /var/log/audit/
/dev/sda2 24G 10.4G 13.6G 43% /var/log/audit

If the audit records are not written to a partition made specifically for audit records (/var/log/audit is a separate partition), determine the amount of space being used by other files in the partition with the following command:

$ sudo du -sh [audit_partition]
1.8G /var/log/audit

If the audit record partition is not allocated for sufficient storage capacity, this is a finding.

Note: The partition size needed to capture a week of audit records is based on the activity level of the system and the total storage capacity available. Typically 10.0 GB of storage space for audit records should be sufficient.

```
---
SV-230479:
Old: 
```
Verify the audit system off-loads audit records onto a different system or
media from the system being audited with the following command:

    $ sudo grep @@ /etc/rsyslog.conf /etc/rsyslog.d/*.conf

    /etc/rsyslog.conf:*.* @@[remoteloggingserver]:[port]

    If a remote server is not configured, or the line is commented out, ask the
System Administrator to indicate how the audit logs are off-loaded to a
different system or media.

    If there is no evidence that the audit logs are being off-loaded to another
system or media, this is a finding.

```

Updated:
```
Verify the audit system offloads audit records onto a different system or media from the system being audited with the following command:

     $ sudo grep @@ /etc/rsyslog.conf /etc/rsyslog.d/*.conf

     /etc/rsyslog.conf:*.* @@[logaggregationserver.example.mil]:[port]

If a remote server is not configured, or the line is commented out, ask the system administrator to indicate how the audit logs are offloaded to a different system or media. 

If there is no evidence that the audit logs are being offloaded to another system or media, this is a finding.

```
---
SV-230481:
Old: 
```
Verify the operating system encrypts audit records off-loaded onto a
different system or media from the system being audited with the following
commands:

    $ sudo grep -i '$DefaultNetstreamDriver' /etc/rsyslog.conf
/etc/rsyslog.d/*.conf

    /etc/rsyslog.conf:$DefaultNetstreamDriver gtls

    If the value of the "$DefaultNetstreamDriver" option is not set to
"gtls" or the line is commented out, this is a finding.

    $ sudo grep -i '$ActionSendStreamDriverMode' /etc/rsyslog.conf
/etc/rsyslog.d/*.conf

    /etc/rsyslog.conf:$ActionSendStreamDriverMode 1

    If the value of the "$ActionSendStreamDriverMode" option is not set to
"1" or the line is commented out, this is a finding.

    If either of the definitions above are set, ask the System Administrator to
indicate how the audit logs are off-loaded to a different system or media.

    If there is no evidence that the transfer of the audit logs being
off-loaded to another system or media is encrypted, this is a finding.

```

Updated:
```
Verify the operating system encrypts audit records off-loaded onto a different system or media from the system being audited with the following commands:

$ sudo grep -i '$DefaultNetstreamDriver' /etc/rsyslog.conf /etc/rsyslog.d/*.conf

/etc/rsyslog.conf:$DefaultNetstreamDriver gtls

If the value of the "$DefaultNetstreamDriver" option is not set to "gtls" or the line is commented out, this is a finding.

$ sudo grep -i '$ActionSendStreamDriverMode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf

/etc/rsyslog.conf:$ActionSendStreamDriverMode 1

If the value of the "$ActionSendStreamDriverMode" option is not set to "1" or the line is commented out, this is a finding.

If neither of the definitions above are set, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media. 

If there is no evidence that the transfer of the audit logs being off-loaded to another system or media is encrypted, this is a finding.

```
---
SV-230485:
Old: 
```
Verify RHEL 8 disables the chrony daemon from acting as a server with the
following command:

    $ sudo grep -w 'port' /etc/chrony.conf

    port 0

    If the "port" option is not set to "0", is commented out or missing,
this is a finding.

```

Updated:
```
Note: If the system is approved and documented by the information system security officer (ISSO) to function as an NTP time server, this requirement is Not Applicable.

Verify RHEL 8 disables the chrony daemon from acting as a server with the following command:

     $ sudo grep -w 'port' /etc/chrony.conf
     port 0

If the "port" option is not set to "0", is commented out or missing, this is a finding.

```
---
SV-230486:
Old: 
```
Verify RHEL 8 disables network management of the chrony daemon with the
following command:

    $ sudo grep -w 'cmdport' /etc/chrony.conf

    cmdport 0

    If the "cmdport" option is not set to "0", is commented out or missing,
this is a finding.

```

Updated:
```
Note: If the system is approved and documented by the information system security officer (ISSO) to function as an NTP time server, this requirement is Not Applicable.

Verify RHEL 8 disables network management of the chrony daemon with the following command:

     $ sudo grep -w 'cmdport' /etc/chrony.conf
     cmdport 0

If the "cmdport" option is not set to "0", is commented out or missing, this is a finding.

```
---
SV-230491:
Old: 
```
Verify RHEL 8 enables kernel page-table isolation with the following
commands:

    $ sudo grub2-editenv - list | grep pti

    kernelopts=root=/dev/mapper/rhel-root ro crashkernel=auto
resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet
fips=1 audit=1 audit_backlog_limit=8192 pti=on
boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82

    If the "pti" entry does not equal "on", is missing, or the line is
commented out, this is a finding.

    Check that kernel page-table isolation is enabled by default to persist in
kernel updates:

    $ sudo grep audit /etc/default/grub

    GRUB_CMDLINE_LINUX="pti=on"

    If "pti" is not set to "on", is missing or commented out, this is a
finding.

```

Updated:
```
Verify RHEL 8 enables kernel page-table isolation with the following commands:

$ sudo grub2-editenv list | grep pti

kernelopts=root=/dev/mapper/rhel-root ro crashkernel=auto resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet fips=1 audit=1 audit_backlog_limit=8192 pti=on boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82

If the "pti" entry does not equal "on", is missing, or the line is commented out, this is a finding.

Check that kernel page-table isolation is enabled by default to persist in kernel updates: 

$ sudo grep pti /etc/default/grub

GRUB_CMDLINE_LINUX="pti=on"

If "pti" is not set to "on", is missing or commented out, this is a finding.

```
---
SV-230498:
Old: 
```
Verify the operating system disables the ability to load the cramfs kernel
module.

    $ sudo grep -ri cramfs /etc/modprobe.d/* | grep -i "/bin/true"

    install cramfs /bin/true

    If the command does not return any output, or the line is commented out,
and use of the cramfs protocol is not documented with the Information System
Security Officer (ISSO) as an operational requirement, this is a finding.

    Verify the operating system disables the ability to use the cramfs kernel
module.

    Check to see if the cramfs kernel module is disabled with the following
command:

    $ sudo grep -ri cramfs /etc/modprobe.d/* | grep -i "blacklist"

    blacklist cramfs

    If the command does not return any output or the output is not "blacklist
cramfs", and use of the cramfs kernel module is not documented with the
Information System Security Officer (ISSO) as an operational requirement, this
is a finding.

```

Updated:
```
Verify the operating system disables the ability to load the cramfs kernel module.

$ sudo grep -r cramfs /etc/modprobe.d/* | grep "/bin/true"

install cramfs /bin/true

If the command does not return any output, or the line is commented out, and use of the cramfs protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Verify the operating system disables the ability to use the cramfs kernel module.

Check to see if the cramfs kernel module is disabled with the following command:

$ sudo grep -r cramfs /etc/modprobe.d/* | grep "blacklist"

blacklist cramfs

If the command does not return any output or the output is not "blacklist cramfs", and use of the cramfs kernel module is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

```
---
SV-230499:
Old: 
```
Verify the operating system disables the ability to load the firewire-core
kernel module.

    $ sudo grep -ri firewire-core /etc/modprobe.d/* | grep -i "/bin/true"

    install firewire-core /bin/true

    If the command does not return any output, or the line is commented out,
and use of the firewire-core protocol is not documented with the Information
System Security Officer (ISSO) as an operational requirement, this is a finding.

    Verify the operating system disables the ability to use the firewire-core
kernel module.

    Check to see if the firewire-core kernel module is disabled with the
following command:

    $ sudo grep -ri firewire-core /etc/modprobe.d/* | grep -i "blacklist"

    blacklist firewire-core

    If the command does not return any output or the output is not "blacklist
firewire-core", and use of the firewire-core kernel module is not documented
with the Information System Security Officer (ISSO) as an operational
requirement, this is a finding.

```

Updated:
```
Verify the operating system disables the ability to load the firewire-core kernel module.

$ sudo grep -r firewire-core /etc/modprobe.d/* | grep "/bin/true"

install firewire-core /bin/true

If the command does not return any output, or the line is commented out, and use of the firewire-core protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Verify the operating system disables the ability to use the firewire-core kernel module.

Check to see if the firewire-core kernel module is disabled with the following command:

$ sudo grep -r firewire-core /etc/modprobe.d/* | grep "blacklist"

blacklist firewire-core

If the command does not return any output or the output is not "blacklist firewire-core", and use of the firewire-core kernel module is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

```
---
SV-230507:
Old: 
```
If the device or operating system does not have a Bluetooth adapter
installed, this requirement is not applicable.

    This requirement is not applicable to mobile devices (smartphones and
tablets), where the use of Bluetooth is a local AO decision.

    Determine if Bluetooth is disabled with the following command:

    $ sudo grep bluetooth /etc/modprobe.d/*

    /etc/modprobe.d/bluetooth.conf:install bluetooth /bin/true

    If the Bluetooth driver blacklist entry is missing, a Bluetooth driver is
determined to be in use, and the collaborative computing device has not been
authorized for use, this is a finding.

```

Updated:
```
If the device or operating system does not have a Bluetooth adapter installed, this requirement is not applicable.

This requirement is not applicable to mobile devices (smartphones and tablets), where the use of Bluetooth is a local AO decision.

Determine if Bluetooth is disabled with the following command:

$ sudo grep bluetooth /etc/modprobe.d/*

/etc/modprobe.d/bluetooth.conf:install bluetooth /bin/true

If the Bluetooth driver blacklist entry is missing, a Bluetooth driver is determined to be in use, and the collaborative computing device has not been authorized for use, this is a finding.

Verify the operating system disables the ability to use Bluetooth with the following command:  
 
$ sudo grep -r bluetooth /etc/modprobe.d | grep -i "blacklist" | grep -v "^#" 
 
blacklist bluetooth 
 
If the command does not return any output or the output is not "blacklist bluetooth", and use of Bluetooth is not documented with the ISSO as an operational requirement, this is a finding.

```
---
SV-230520:
Old: 
```
Verify "/var/tmp" is mounted with the "nodev" option:

    $ sudo mount | grep /var/tmp

    /dev/mapper/rhel-var-log-audit on /var/tmp type xfs
(rw,nodev,nosuid,noexec,seclabel)

    Verify that the "nodev" option is configured for /var/tmp:

    $ sudo cat /etc/fstab | grep /var/tmp

    /dev/mapper/rhel-var-log-audit /var/tmp xfs defaults,nodev,nosuid,noexec 0 0

    If results are returned and the "nodev" option is missing, or if /var/tmp
is mounted without the "nodev" option, this is a finding.

```

Updated:
```
Verify "/var/tmp" is mounted with the "nodev" option:

$ sudo mount | grep /var/tmp

/dev/mapper/rhel-var-tmp on /var/tmp type xfs (rw,nodev,nosuid,noexec,seclabel)

Verify that the "nodev" option is configured for /var/tmp:

$ sudo cat /etc/fstab | grep /var/tmp

/dev/mapper/rhel-var-tmp /var/tmp xfs defaults,nodev,nosuid,noexec 0 0

If results are returned and the "nodev" option is missing, or if /var/tmp is mounted without the "nodev" option, this is a finding.

```
---
SV-230521:
Old: 
```
Verify "/var/tmp" is mounted with the "nosuid" option:

    $ sudo mount | grep /var/tmp

    /dev/mapper/rhel-var-log-audit on /var/tmp type xfs
(rw,nodev,nosuid,noexec,seclabel)

    Verify that the "nosuid" option is configured for /var/tmp:

    $ sudo cat /etc/fstab | grep /var/tmp

    /dev/mapper/rhel-var-log-audit /var/tmp xfs defaults,nodev,nosuid,noexec 0 0

    If results are returned and the "nosuid" option is missing, or if
/var/tmp is mounted without the "nosuid" option, this is a finding.

```

Updated:
```
Verify "/var/tmp" is mounted with the "nosuid" option:

$ sudo mount | grep /var/tmp

/dev/mapper/rhel-var-tmp on /var/tmp type xfs (rw,nodev,nosuid,noexec,seclabel)

Verify that the "nosuid" option is configured for /var/tmp:

$ sudo cat /etc/fstab | grep /var/tmp

/dev/mapper/rhel-var-tmp /var/tmp xfs defaults,nodev,nosuid,noexec 0 0

If results are returned and the "nosuid" option is missing, or if /var/tmp is mounted without the "nosuid" option, this is a finding.

```
---
SV-230522:
Old: 
```
Verify "/var/tmp" is mounted with the "noexec" option:

    $ sudo mount | grep /var/tmp

    /dev/mapper/rhel-var-log-audit on /var/tmp type xfs
(rw,nodev,nosuid,noexec,seclabel)

    Verify that the "noexec" option is configured for /var/tmp:

    $ sudo cat /etc/fstab | grep /var/tmp

    /dev/mapper/rhel-var-log-audit /var/tmp xfs defaults,nodev,nosuid,noexec 0 0

    If results are returned and the "noexec" option is missing, or if
/var/tmp is mounted without the "noexec" option, this is a finding.

```

Updated:
```
Verify "/var/tmp" is mounted with the "noexec" option:

$ sudo mount | grep /var/tmp

/dev/mapper/rhel-var-tmp on /var/tmp type xfs (rw,nodev,nosuid,noexec,seclabel)

Verify that the "noexec" option is configured for /var/tmp:

$ sudo cat /etc/fstab | grep /var/tmp

/dev/mapper/rhel-var-tmp /var/tmp xfs defaults,nodev,nosuid,noexec 0 0

If results are returned and the "noexec" option is missing, or if /var/tmp is mounted without the "noexec" option, this is a finding.

```
---
SV-230527:
Old: 
```
Verify the SSH server is configured to force frequent session key
renegotiation with the following command:

    $ sudo grep -i RekeyLimit /etc/ssh/sshd_config

    RekeyLimit 1G 1h

    If "RekeyLimit" does not have a maximum data amount and maximum time
defined, is missing or commented out, this is a finding.

```

Updated:
```
Verify the SSH server is configured to force frequent session key renegotiation with the following command:

$ sudo grep -ir RekeyLimit /etc/ssh/sshd_config*

RekeyLimit 1G 1h

If "RekeyLimit" does not have a maximum data amount and maximum time defined, is missing or commented out, this is a finding.
If conflicting results are returned, this is a finding.

```
---
SV-230535:
Old: 
```
Verify RHEL 8 will not accept IPv6 ICMP redirect messages.

    Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

    Check the value of the default "accept_redirects" variables with the
following command:

    $ sudo sysctl net.ipv6.conf.default.accept_redirects

    net.ipv6.conf.default.accept_redirects = 0

    If the returned line does not have a value of "0", a line is not
returned, or the line is commented out, this is a finding.

```

Updated:
```
Verify RHEL 8 will not accept IPv6 ICMP redirect messages.

Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

Check the value of the default "accept_redirects" variables with the following command:

$ sudo sysctl net.ipv6.conf.default.accept_redirects

net.ipv6.conf.default.accept_redirects = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv6.conf.default.accept_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv6.conf.default.accept_redirects = 0

If "net.ipv6.conf.default.accept_redirects" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-230536:
Old: 
```
Verify RHEL 8 does not IPv4 ICMP redirect messages.

    Note: If IPv4 is disabled on the system, this requirement is Not Applicable.

    Check the value of the "all send_redirects" variables with the following
command:

    $ sudo sysctl net.ipv4.conf.all.send_redirects

    net.ipv4.conf.all.send_redirects = 0

    If the returned line does not have a value of "0", or a line is not
returned, this is a finding.

```

Updated:
```
Verify RHEL 8 does not IPv4 ICMP redirect messages.

Check the value of the "all send_redirects" variables with the following command:

$ sudo sysctl net.ipv4.conf.all.send_redirects

net.ipv4.conf.all.send_redirects = 0

If the returned line does not have a value of "0", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.conf.all.send_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv4.conf.all.send_redirects = 0

If "net.ipv4.conf.all.send_redirects" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-230537:
Old: 
```
Verify RHEL 8 does not respond to ICMP echoes sent to a broadcast address.

    Note: If IPv4 is disabled on the system, this requirement is Not Applicable.
    Check the value of the "icmp_echo_ignore_broadcasts" variable with the
following command:

    $ sudo sysctl net.ipv4.icmp_echo_ignore_broadcasts

    net.ipv4.icmp_echo_ignore_broadcasts = 1

    If the returned line does not have a value of "1", a line is not
returned, or the retuned line is commented out, this is a finding.

```

Updated:
```
Verify RHEL 8 does not respond to ICMP echoes sent to a broadcast address.

Check the value of the "icmp_echo_ignore_broadcasts" variable with the following command:

$ sudo sysctl net.ipv4.icmp_echo_ignore_broadcasts

net.ipv4.icmp_echo_ignore_broadcasts = 1

If the returned line does not have a value of "1", a line is not returned, or the retuned line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.icmp_echo_ignore_broadcasts /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv4.icmp_echo_ignore_broadcasts = 1

If "net.ipv4.icmp_echo_ignore_broadcasts" is not set to "1", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-230538:
Old: 
```
Verify RHEL 8 does not accept IPv6 source-routed packets.

    Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

    Check the value of the accept source route variable with the following
command:

    $ sudo sysctl net.ipv6.conf.all.accept_source_route

    net.ipv6.conf.all.accept_source_route = 0

    If the returned line does not have a value of "0", a line is not
returned, or the line is commented out, this is a finding.

```

Updated:
```
Verify RHEL 8 does not accept IPv6 source-routed packets.

Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

Check the value of the accept source route variable with the following command:

$ sudo sysctl net.ipv6.conf.all.accept_source_route

net.ipv6.conf.all.accept_source_route = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv6.conf.all.accept_source_route /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv6.conf.all.accept_source_route = 0

If "net.ipv6.conf.all.accept_source_route" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-230539:
Old: 
```
Verify RHEL 8 does not accept IPv6 source-routed packets by default.

    Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

    Check the value of the accept source route variable with the following
command:

    $ sudo sysctl net.ipv6.conf.default.accept_source_route

    net.ipv6.conf.default.accept_source_route = 0

    If the returned line does not have a value of "0", a line is not
returned, or the line is commented out, this is a finding.

```

Updated:
```
Verify RHEL 8 does not accept IPv6 source-routed packets by default.

Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

Check the value of the accept source route variable with the following command:

$ sudo sysctl net.ipv6.conf.default.accept_source_route

net.ipv6.conf.default.accept_source_route = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv6.conf.default.accept_source_route /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv6.conf.default.accept_source_route = 0

If "net.ipv6.conf.default.accept_source_route" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-230540:
Old: 
```
Verify RHEL 8 is not performing packet forwarding, unless the system is a
router.

    Note: If either IPv4 or IPv6 is disabled on the system, this requirement
only applies to the active internet protocol version.

    Check to see if IP forwarding is enabled using the following commands:

    $ sudo sysctl  net.ipv4.ip_forward

    net.ipv4.ip_forward = 0

    $ sudo sysctl net.ipv6.conf.all.forwarding

    net.ipv6.conf.all.forwarding = 0

    If IP forwarding value is not "0" and is not documented with the
Information System Security Officer (ISSO) as an operational requirement, this
is a finding.

```

Updated:
```
Verify RHEL 8 is not performing IPv6 packet forwarding, unless the system is a router.

Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

Check that IPv6 forwarding is disabled using the following commands:

$ sudo sysctl net.ipv6.conf.all.forwarding

net.ipv6.conf.all.forwarding = 0

If the IPv6 forwarding value is not "0" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv6.conf.all.forwarding /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv6.conf.all.forwarding = 0

If "net.ipv6.conf.all.forwarding" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-230541:
Old: 
```
Verify RHEL 8 does not accept router advertisements on all IPv6 interfaces,
unless the system is a router.

    Note: If IPv6 is disabled on the system, this requirement is not applicable.

    Check to see if router advertisements are not accepted by using the
following command:

    $ sudo sysctl  net.ipv6.conf.all.accept_ra

    net.ipv6.conf.all.accept_ra = 0

    If the "accept_ra" value is not "0" and is not documented with the
Information System Security Officer (ISSO) as an operational requirement, this
is a finding.

```

Updated:
```
Verify RHEL 8 does not accept router advertisements on all IPv6 interfaces, unless the system is a router.

Note: If IPv6 is disabled on the system, this requirement is not applicable.

Check to see if router advertisements are not accepted by using the following command:

$ sudo sysctl  net.ipv6.conf.all.accept_ra

net.ipv6.conf.all.accept_ra = 0

If the "accept_ra" value is not "0" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv6.conf.all.accept_ra /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv6.conf.all.accept_ra = 0

If "net.ipv6.conf.all.accept_ra" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-230542:
Old: 
```
Verify RHEL 8 does not accept router advertisements on all IPv6 interfaces
by default, unless the system is a router.

    Note: If IPv6 is disabled on the system, this requirement is not applicable.

    Check to see if router advertisements are not accepted by default by using
the following command:

    $ sudo sysctl  net.ipv6.conf.default.accept_ra

    net.ipv6.conf.default.accept_ra = 0

    If the "accept_ra" value is not "0" and is not documented with the
Information System Security Officer (ISSO) as an operational requirement, this
is a finding.

```

Updated:
```
Verify RHEL 8 does not accept router advertisements on all IPv6 interfaces by default, unless the system is a router.

Note: If IPv6 is disabled on the system, this requirement is not applicable.

Check to see if router advertisements are not accepted by default by using the following command:

$ sudo sysctl  net.ipv6.conf.default.accept_ra

net.ipv6.conf.default.accept_ra = 0

If the "accept_ra" value is not "0" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv6.conf.default.accept_ra /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv6.conf.default.accept_ra = 0

If "net.ipv6.conf.default.accept_ra" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-230543:
Old: 
```
Verify RHEL 8 does not allow interfaces to perform Internet Protocol
version 4 (IPv4) ICMP redirects by default.

    Note: If IPv4 is disabled on the system, this requirement is Not Applicable.

    Check the value of the "default send_redirects" variables with the
following command:

    $ sudo sysctl net.ipv4.conf.default.send_redirects

    net.ipv4.conf.default.send_redirects=0

    If the returned line does not have a value of "0", or a line is not
returned, this is a finding.

```

Updated:
```
Verify RHEL 8 does not allow interfaces to perform Internet Protocol version 4 (IPv4) ICMP redirects by default.

Check the value of the "default send_redirects" variables with the following command:

$ sudo sysctl net.ipv4.conf.default.send_redirects

net.ipv4.conf.default.send_redirects=0

If the returned line does not have a value of "0", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.conf.default.send_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv4.conf.default.send_redirects = 0

If "net.ipv4.conf.default.send_redirects" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-230544:
Old: 
```
Verify RHEL 8 ignores IPv6 ICMP redirect messages.

    Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

    Check the value of the "accept_redirects" variables with the following
command:

    $ sudo sysctl net.ipv6.conf.all.accept_redirects

    net.ipv6.conf.all.accept_redirects = 0

    If the returned line does not have a value of "0", a line is not
returned, or the line is commented out, this is a finding.

```

Updated:
```
Verify RHEL 8 ignores IPv6 ICMP redirect messages.

Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

Check the value of the "accept_redirects" variables with the following command:

$ sudo sysctl net.ipv6.conf.all.accept_redirects

net.ipv6.conf.all.accept_redirects = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv6.conf.all.accept_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv6.conf.all.accept_redirects = 0

If "net.ipv6.conf.all.accept_redirects" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-230545:
Old: 
```
Verify RHEL 8 prevents privilege escalation thru the kernel by disabling
access to the bpf syscall with the following commands:

    $ sudo sysctl kernel.unprivileged_bpf_disabled

    kernel.unprivileged_bpf_disabled = 1

    If the returned line does not have a value of "1", or a line is not
returned, this is a finding.

```

Updated:
```
Verify RHEL 8 prevents privilege escalation thru the kernel by disabling access to the bpf syscall with the following commands:

$ sudo sysctl kernel.unprivileged_bpf_disabled

kernel.unprivileged_bpf_disabled = 1

If the returned line does not have a value of "1", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r kernel.unprivileged_bpf_disabled /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: kernel.unprivileged_bpf_disabled = 1

If "kernel.unprivileged_bpf_disabled" is not set to "1", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-230546:
Old: 
```
Verify RHEL 8 restricts usage of ptrace to descendant processes with the
following commands:

    $ sudo sysctl kernel.yama.ptrace_scope

    kernel.yama.ptrace_scope = 1

    If the returned line does not have a value of "1", or a line is not
returned, this is a finding.

```

Updated:
```
Verify RHEL 8 restricts usage of ptrace to descendant processes with the following commands:

$ sudo sysctl kernel.yama.ptrace_scope

kernel.yama.ptrace_scope = 1

If the returned line does not have a value of "1", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r kernel.yama.ptrace_scope /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: kernel.yama.ptrace_scope = 1

If "kernel.yama.ptrace_scope" is not set to "1", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-230547:
Old: 
```
Verify RHEL 8 restricts exposed kernel pointer addresses access with the
following commands:

    $ sudo sysctl kernel.kptr_restrict

    kernel.kptr_restrict = 1

    If the returned line does not have a value of "1", or a line is not
returned, this is a finding.

```

Updated:
```
Verify RHEL 8 restricts exposed kernel pointer addresses access with the following commands:

$ sudo sysctl kernel.kptr_restrict

kernel.kptr_restrict = 1

If the returned line does not have a value of "1" or "2", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r kernel.kptr_restrict /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: kernel.kptr_restrict = 1

If "kernel.kptr_restrict" is not set to "1" or "2", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-230548:
Old: 
```
Verify RHEL 8 disables the use of user namespaces with the following
commands:

    Note: User namespaces are used primarily for Linux containers.  If
containers are in use, this requirement is not applicable.

    $ sudo sysctl user.max_user_namespaces

    user.max_user_namespaces = 0

    If the returned line does not have a value of "0", or a line is not
returned, this is a finding.

```

Updated:
```
Verify RHEL 8 disables the use of user namespaces with the following commands:

Note: User namespaces are used primarily for Linux containers. If containers are in use, this requirement is not applicable.

$ sudo sysctl user.max_user_namespaces

user.max_user_namespaces = 0

If the returned line does not have a value of "0", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r user.max_user_namespaces /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: user.max_user_namespaces = 0

If "user.max_user_namespaces" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-230549:
Old: 
```
Verify RHEL 8 uses reverse path filtering on all IPv4 interfaces with the
following commands:

    $ sudo sysctl net.ipv4.conf.all.rp_filter

    net.ipv4.conf.all.rp_filter = 1

    If the returned line does not have a value of "1", or a line is not
returned, this is a finding.

```

Updated:
```
Verify RHEL 8 uses reverse path filtering on all IPv4 interfaces with the following commands:

$ sudo sysctl net.ipv4.conf.all.rp_filter

net.ipv4.conf.all.rp_filter = 1

If the returned line does not have a value of "1" or "2", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.conf.all.rp_filter /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv4.conf.all.rp_filter = 1

If "net.ipv4.conf.all.rp_filter" is not set to "1" or "2", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-230552:
Old: 
```
Verify the file integrity tool is configured to verify ACLs.

    Note: AIDE is highly configurable at install time. This requirement assumes
the "aide.conf" file is under the "/etc" directory.

    If AIDE is not installed, ask the System Administrator how file integrity
checks are performed on the system.

    Use the following command to determine if the file is in a location other
than "/etc/aide/aide.conf":

    $ sudo find / -name aide.conf

    Check the "aide.conf" file to determine if the "acl" rule has been
added to the rule list being applied to the files and directories selection
lists with the following command:

    $ sudo egrep "[+]?acl" /etc/aide.conf

    VarFile = OwnerMode+n+l+X+acl

    If the "acl" rule is not being used on all selection lines in the
"/etc/aide.conf" file, is commented out, or ACLs are not being checked by
another file integrity tool, this is a finding.

```

Updated:
```
Verify the file integrity tool is configured to verify ACLs.

Note: AIDE is highly configurable at install time. This requirement assumes the "aide.conf" file is under the "/etc" directory.

If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system.

Use the following command to determine if the file is in a location other than "/etc/aide/aide.conf":

     $ sudo find / -name aide.conf

Check the "aide.conf" file to determine if the "acl" rule has been added to the rule list being applied to the files and directories selection lists with the following command:

     $ sudo grep -E "[+]?acl" /etc/aide.conf

     VarFile = OwnerMode+n+l+X+acl

If the "acl" rule is not being used on all selection lines in the "/etc/aide.conf" file, is commented out, or ACLs are not being checked by another file integrity tool, this is a finding.

```
---
SV-230553:
Old: 
```
Verify that the system is configured to boot to the command line:

    $ systemctl get-default
    multi-user.target

    If the system default target is not set to "multi-user.target" and the
Information System Security Officer (ISSO) lacks a documented requirement for a
graphical user interface, this is a finding.

    Verify that a graphical user interface is not installed:

    $ rpm -qa | grep xorg | grep server

    Ask the System Administrator if use of a graphical user interface is an
operational requirement.

    If the use of a graphical user interface on the system is not documented
with the ISSO, this is a finding.

```

Updated:
```
Verify that a graphical user interface is not installed:

$ rpm -qa | grep xorg | grep server

Ask the System Administrator if use of a graphical user interface is an operational requirement.

If the use of a graphical user interface on the system is not documented with the ISSO, this is a finding.

```
---
SV-230555:
Old: 
```
Verify X11Forwarding is disabled with the following command:

    $ sudo grep -i x11forwarding /etc/ssh/sshd_config | grep -v "^#"

    X11Forwarding no

    If the "X11Forwarding" keyword is set to "yes" and is not documented
with the Information System Security Officer (ISSO) as an operational
requirement or is missing, this is a finding.

```

Updated:
```
Verify X11Forwarding is disabled with the following command:

$ sudo grep -ir x11forwarding /etc/ssh/sshd_config* | grep -v "^#"

X11Forwarding no

If the "X11Forwarding" keyword is set to "yes" and is not documented with the Information System Security Officer (ISSO) as an operational requirement or is missing, this is a finding.
If conflicting results are returned, this is a finding.

```
---
SV-230556:
Old: 
```
Verify the SSH daemon prevents remote hosts from connecting to the proxy
display.

    Check the SSH X11UseLocalhost setting with the following command:

    # sudo grep -i x11uselocalhost /etc/ssh/sshd_config
    X11UseLocalhost yes

    If the "X11UseLocalhost" keyword is set to "no", is missing, or is
commented out, this is a finding.

```

Updated:
```
Verify the SSH daemon prevents remote hosts from connecting to the proxy display.

Check the SSH X11UseLocalhost setting with the following command:

# sudo grep -ir x11uselocalhost /etc/ssh/sshd_config*
X11UseLocalhost yes

If the "X11UseLocalhost" keyword is set to "no", is missing, or is commented out, this is a finding.
If conflicting results are returned, this is a finding.

```
---
SV-237642:
Old: 
```
Verify that the sudoers security policy is configured to use the invoking
user's password for privilege escalation.

    $ sudo egrep -i '(!rootpw|!targetpw|!runaspw)' /etc/sudoers
/etc/sudoers.d/* | grep -v '#'

    /etc/sudoers:Defaults !targetpw
    /etc/sudoers:Defaults !rootpw
    /etc/sudoers:Defaults !runaspw

    If no results are returned, this is a finding
    If "Defaults !targetpw" is not defined, this is a finding.
    If "Defaults !rootpw" is not defined, this is a finding.
    If "Defaults !runaspw" is not defined, this is a finding.

```

Updated:
```
Verify that the sudoers security policy is configured to use the invoking user's password for privilege escalation.

     $ sudo grep -Eir '(rootpw|targetpw|runaspw)' /etc/sudoers /etc/sudoers.d* | grep -v '#'

     /etc/sudoers:Defaults !targetpw
     /etc/sudoers:Defaults !rootpw
     /etc/sudoers:Defaults !runaspw

If conflicting results are returned, this is a finding.
If "Defaults !targetpw" is not defined, this is a finding.
If "Defaults !rootpw" is not defined, this is a finding.
If "Defaults !runaspw" is not defined, this is a finding.

```
---
SV-237643:
Old: 
```
Verify the operating system requires re-authentication when using the
"sudo" command to elevate privileges.

    $ sudo grep -i 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/*
    /etc/sudoers:Defaults timestamp_timout=0

    If "timestamp_timeout" is set to a negative number, is commented out, or
no results are returned, this is a finding.

```

Updated:
```
Verify the operating system requires re-authentication when using the "sudo" command to elevate privileges.

$ sudo grep -ir 'timestamp_timeout' /etc/sudoers /etc/sudoers.d
/etc/sudoers:Defaults timestamp_timeout=0

If conflicting results are returned, this is a finding.

If "timestamp_timeout" is set to a negative number, is commented out, or no results are returned, this is a finding.

```
---
SV-244521:
Old: 
```
For systems that use BIOS, this is Not Applicable.

    Verify that a unique name is set as the "superusers" account:

    $ sudo grep -iw "superusers" /boot/efi/EFI/redhat/grub.cfg
    set superusers="[someuniquestringhere]"
    export superusers

    If "superusers" is not set to a unique name or is missing a name, this is
a finding.

```

Updated:
```
For systems that use BIOS, this is Not Applicable.

Verify that a unique name is set as the "superusers" account:

$ sudo grep -iw "superusers" /boot/efi/EFI/redhat/grub.cfg
set superusers="[someuniquestringhere]"
export superusers

If "superusers" is identical to any OS account name or is missing a name, this is a finding.

```
---
SV-244522:
Old: 
```
For systems that use UEFI, this is Not Applicable.

    Verify that a unique name is set as the "superusers" account:

    $ sudo grep -iw "superusers" /boot/grub2/grub.cfg
    set superusers="[someuniquestringhere]"
    export superusers

    If "superusers" is not set to a unique name or is missing a name, this is
a finding.

```

Updated:
```
For systems that use UEFI, this is Not Applicable.

Verify that a unique name is set as the "superusers" account:

$ sudo grep -iw "superusers" /boot/grub2/grub.cfg
set superusers="[someuniquestringhere]"
export superusers

If "superusers" is identical to any OS account name or is missing a name, this is a finding.

```
---
SV-244524:
Old: 
```
Verify that pam_unix.so module is configured to use sha512.

    Check that pam_unix.so module is configured to use sha512 in
/etc/pam.d/system-auth with the following command:

    $ sudo grep password /etc/pam.d/system-auth | grep pam_unix

    password sufficient pam_unix.so sha512 rounds=5000

    If "sha512" is missing, or is commented out, this is a finding.

```

Updated:
```
Verify that pam_unix.so module is configured to use sha512.

Check that pam_unix.so module is configured to use sha512 in /etc/pam.d/system-auth with the following command:

$ sudo grep password /etc/pam.d/system-auth | grep pam_unix

password sufficient pam_unix.so sha512

If "sha512" is missing, or is commented out, this is a finding.

```
---
SV-244525:
Old: 
```
Verify all network connections associated with SSH traffic are
automatically terminated at the end of the session or after 10 minutes of
inactivity.

    Check that the "ClientAliveInterval" variable is set to a value of
"600" or less by performing the following command:

    $ sudo grep -i clientalive /etc/ssh/sshd_config

    ClientAliveInterval 600
    ClientAliveCountMax 0

    If "ClientAliveInterval" does not exist, does not have a value of "600"
or less in "/etc/ssh/sshd_config", or is commented out, this is a finding.

```

Updated:
```
Verify the SSH server automatically terminates a user session after the SSH client has been unresponsive for 10 minutes.

Check that the "ClientAliveInterval" variable is set to a value of "600" or less by performing the following command:

     $ sudo grep -ir clientaliveinterval /etc/ssh/sshd_config*

     ClientAliveInterval 600

If "ClientAliveInterval" does not exist, does not have a value of "600" or less in "/etc/ssh/sshd_config" or is commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-244526:
Old: 
```
Verify that system-wide crypto policies are in effect:

$ sudo grep -i crypto_policy /etc/sysconfig/sshd

# crypto_policy=

If the "crypto_policy" is uncommented, this is a finding.

```

Updated:
```
Verify that system-wide crypto policies are in effect:

$ sudo grep CRYPTO_POLICY /etc/sysconfig/sshd

# CRYPTO_POLICY=

If the "CRYPTO_POLICY " is uncommented, this is a finding.

```
---
SV-244528:
Old: 
```
Verify the SSH daemon does not allow GSSAPI authentication with the
following command:

    $ sudo grep -i GSSAPIAuthentication  /etc/ssh/sshd_config

    GSSAPIAuthentication no

    If the value is returned as "yes", the returned line is commented out, no
output is returned, or has not been documented with the ISSO, this is a finding.

```

Updated:
```
Verify the SSH daemon does not allow GSSAPI authentication with the following command:

$ sudo grep -ir GSSAPIAuthentication  /etc/ssh/sshd_config*

GSSAPIAuthentication no

If the value is returned as "yes", the returned line is commented out, no output is returned, or has not been documented with the ISSO, this is a finding.
If conflicting results are returned, this is a finding.

```
---
SV-244529:
Old: 
```
Verify that a separate file system/partition has been created for
"/var/tmp".

    Check that a file system/partition has been created for "/var/tmp" with
the following command:

    $ sudo grep /var/tmp /etc/fstab

    UUID=c274f65f /var/tmp xfs noatime,nobarrier 1 2

    If a separate entry for "/var/tmp" is not in use, this is a finding.

```

Updated:
```
Verify that a separate file system has been created for "/var/tmp".

Check that a file system has been created for "/var/tmp" with the following command:

     $ sudo grep /var/tmp /etc/fstab

     /dev/mapper/...   /var/tmp   xfs   defaults,nodev,noexec,nosuid 0 0

If a separate entry for "/var/tmp" is not in use, this is a finding.

```
---
SV-244530:
Old: 
```
For systems that use BIOS, this is Not Applicable.

    Verify the /boot/efi directory is mounted with the "nosuid" option with
the following command:

    $ sudo mount | grep '\s/boot/efi\s'

    /dev/sda1 on /boot/efi type xfs
(rw,nosuid,relatime,seclabe,attr2,inode64,noquota)

    If the /boot/efi file system does not have the "nosuid" option set, this
is a finding.

```

Updated:
```
For systems that use BIOS, this is Not Applicable.

Verify the /boot/efi directory is mounted with the "nosuid" option with the following command:

$ sudo mount | grep '\s/boot/efi\s'

/dev/sda1 on /boot/efi type vfat (rw,nosuid,relatime,fmask=0077,dmask=0077,codepage=437,iocharset=ascii,shortname=winnt,errors=remount-ro)

If the /boot/efi file system does not have the "nosuid" option set, this is a finding.

```
---
SV-244550:
Old: 
```
Verify RHEL 8 will not accept IPv4 ICMP redirect messages.

    Note: If IPv4 is disabled on the system, this requirement is Not Applicable.

    Check the value of the default "accept_redirects" variables with the
following command:

    $ sudo sysctl net.ipv4.conf.default.accept_redirects

    net.ipv4.conf.default.accept_redirects = 0

    If the returned line does not have a value of "0", a line is not
returned, or the line is commented out, this is a finding.

```

Updated:
```
Verify RHEL 8 will not accept IPv4 ICMP redirect messages.

Check the value of the default "accept_redirects" variables with the following command:

$ sudo sysctl net.ipv4.conf.default.accept_redirects

net.ipv4.conf.default.accept_redirects = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.conf.default.accept_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv4.conf.default.accept_redirects = 0

If "net.ipv4.conf.default.accept_redirects" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-244551:
Old: 
```
Verify RHEL 8 does not accept IPv4 source-routed packets.

    Note: If IPv4 is disabled on the system, this requirement is Not Applicable.

    Check the value of the accept source route variable with the following
command:

    $ sudo sysctl net.ipv4.conf.all.accept_source_route

    net.ipv4.conf.all.accept_source_route = 0

    If the returned line does not have a value of "0", a line is not
returned, or the line is commented out, this is a finding.

```

Updated:
```
Verify RHEL 8 does not accept IPv4 source-routed packets.

Check the value of the accept source route variable with the following command:

$ sudo sysctl net.ipv4.conf.all.accept_source_route

net.ipv4.conf.all.accept_source_route = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.conf.all.accept_source_route /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv4.conf.all.accept_source_route = 0

If "net.ipv4.conf.all.accept_source_route" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-244552:
Old: 
```
Verify RHEL 8 does not accept IPv4 source-routed packets by default.

    Note: If IPv4 is disabled on the system, this requirement is Not Applicable.

    Check the value of the accept source route variable with the following
command:

    $ sudo sysctl net.ipv4.conf.default.accept_source_route

    net.ipv4.conf.default.accept_source_route = 0

    If the returned line does not have a value of "0", a line is not
returned, or the line is commented out, this is a finding.

```

Updated:
```
Verify RHEL 8 does not accept IPv4 source-routed packets by default.

Check the value of the accept source route variable with the following command:

$ sudo sysctl net.ipv4.conf.default.accept_source_route

net.ipv4.conf.default.accept_source_route = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.conf.default.accept_source_route /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv4.conf.default.accept_source_route = 0

If "net.ipv4.conf.default.accept_source_route" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-244553:
Old: 
```
Verify RHEL 8 ignores IPv4 ICMP redirect messages.

    Note: If IPv4 is disabled on the system, this requirement is Not Applicable.

    Check the value of the "accept_redirects" variables with the following
command:

    $ sudo sysctl net.ipv4.conf.all.accept_redirects

    net.ipv4.conf.all.accept_redirects = 0

    If the returned line does not have a value of "0", a line is not
returned, or the line is commented out, this is a finding.

```

Updated:
```
Verify RHEL 8 ignores IPv4 ICMP redirect messages.

Check the value of the "accept_redirects" variables with the following command:

$ sudo sysctl net.ipv4.conf.all.accept_redirects

net.ipv4.conf.all.accept_redirects = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.conf.all.accept_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv4.conf.all.accept_redirects = 0

If "net.ipv4.conf.all.accept_redirects" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-244554:
Old: 
```
Verify RHEL 8 enables hardening for the BPF JIT with the following commands:

    $ sudo sysctl net.core.bpf_jit_harden

    net.core.bpf_jit_harden = 2

    If the returned line does not have a value of "2", or a line is not
returned, this is a finding.

```

Updated:
```
Verify RHEL 8 enables hardening for the BPF JIT with the following commands:

$ sudo sysctl net.core.bpf_jit_harden

net.core.bpf_jit_harden = 2

If the returned line does not have a value of "2", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.core.bpf_jit_harden /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.core.bpf_jit_harden = 2

If "net.core.bpf_jit_harden" is not set to "2", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.

```
---
</details>

#### Fixes:
<details open>
  <summary>Click to expand.</summary>
SV-230226:
Old: 
```
Configure the operating system to display the Standard Mandatory DoD Notice
and Consent Banner before granting access to the system.

    Note: If the system does not have a graphical user interface installed,
this requirement is Not Applicable.

    Add the following lines to the [org/gnome/login-screen] section of the
"/etc/dconf/db/local.d/01-banner-message":

    banner-message-text='You are accessing a U.S. Government (USG) Information
System (IS) that is provided for USG-authorized use only.\
    By using this IS (which includes any device attached to this IS), you
consent to the following conditions:\
    -The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.\
    -At any time, the USG may inspect and seize data stored on this IS.\
    -Communications using, or data stored on, this IS are not private, are
subject to routine monitoring, interception, and search, and may be disclosed
or used for any USG-authorized purpose.\
    -This IS includes security measures (e.g., authentication and access
controls) to protect USG interests--not for your personal benefit or privacy.\
    -Notwithstanding the above, using this IS does not constitute consent to
PM, LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services
by attorneys, psychotherapists, or clergy, and their assistants. Such
communications and work product are private and confidential. See User
Agreement for details. '

    Note: The "\" characters are for formatting only. They will not be displayed on the
graphical interface.

    Run the following command to update the database:

    $ sudo dconf update

```
New:
```
Configure the operating system to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system.

Note: If the system does not have a graphical user interface installed, this requirement is Not Applicable.

Add the following lines to the [org/gnome/login-screen] section of the "/etc/dconf/db/local.d/01-banner-message":

banner-message-text='You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n-At any time, the USG may inspect and seize data stored on this IS.\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details. '

Note: The "\n " characters are for formatting only. They will not be displayed on the graphical interface.

Run the following command to update the database:

$ sudo dconf update

```
---
SV-230229:
Old: 
```
Configure RHEL 8, for PKI-based authentication, to validate certificates by
constructing a certification path (which includes status information) to an
accepted trust anchor.

    Obtain a valid copy of the DoD root CA file from the PKI CA certificate
bundle from cyber.mil and copy the DoD_PKE_CA_chain.pem into the following file:

    /etc/sssd/pki/sssd_auth_ca_db.pem

```
New:
```
Configure RHEL 8, for PKI-based authentication, to validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.

Obtain a valid copy of the DoD root CA file from the PKI CA certificate bundle at cyber.mil and copy into the following file:

/etc/sssd/pki/sssd_auth_ca_db.pem

```
---
SV-230237:
Old: 
```
Configure RHEL 8 to use a FIPS 140-2 approved cryptographic hashing
algorithm for system authentication.

    Edit/modify the following line in the "/etc/pam.d/password-auth" file to
include the sha512 option for pam_unix.so:

    password sufficient pam_unix.so sha512 rounds=5000

```
New:
```
Configure RHEL 8 to use a FIPS 140-2 approved cryptographic hashing algorithm for system authentication.

Edit/modify the following line in the "/etc/pam.d/password-auth" file to include the sha512 option for pam_unix.so:

password sufficient pam_unix.so sha512

```
---
SV-230252:
Old: 
```
Configure the RHEL 8 SSH server to use only ciphers employing FIPS
140-2-approved algorithms by updating the
"/etc/crypto-policies/back-ends/opensshserver.config" file with the following
line:

    -oCiphers=aes256-ctr,aes192-ctr,aes128-ctr

    A reboot is required for the changes to take effect.

```
New:
```
Configure the RHEL 8 SSH server to use only ciphers employing FIPS 140-2-approved algorithms by updating the "/etc/crypto-policies/back-ends/opensshserver.config" file with the following line:

-oCiphers=aes256-ctr,aes192-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com

A reboot is required for the changes to take effect.

```
---
SV-230255:
Old: 
```
Configure the RHEL 8 OpenSSL library to use only DoD-approved TLS
encryption by editing the following line in the
"/etc/crypto-policies/back-ends/opensslcnf.config" file:

    MinProtocol = TLSv1.2

    A reboot is required for the changes to take effect.

```
New:
```
Configure the RHEL 8 OpenSSL library to use only DoD-approved TLS encryption by editing the following line in the "/etc/crypto-policies/back-ends/opensslcnf.config" file:

For versions prior to crypto-policies-20210617-1.gitc776d3e.el8.noarch:
MinProtocol = TLSv1.2

For version crypto-policies-20210617-1.gitc776d3e.el8.noarch and newer:
TLS.MinProtocol = TLSv1.2
DTLS.MinProtocol = DTLSv1.2
A reboot is required for the changes to take effect.

```
---
SV-230257:
Old: 
```
Configure the system commands to be protected from unauthorized access.

    Run the following command, replacing "[FILE]" with any system command
with a mode more permissive than "0755".

    $ sudo chmod 0755 [FILE]

```
New:
```
Configure the system commands to be protected from unauthorized access.

Run the following command, replacing "[FILE]" with any system command with a mode more permissive than "755".

$ sudo chmod 755 [FILE]

```
---
SV-230260:
Old: 
```
Configure the library files to be protected from unauthorized access. Run
the following command, replacing "[FILE]" with any library file with a mode
more permissive than 0755.

    $ sudo chmod 0755 [FILE]

```
New:
```
Configure the library files to be protected from unauthorized access. Run the following command, replacing "[FILE]" with any library file with a mode more permissive than 755.

$ sudo chmod 755 [FILE]

```
---
SV-230263:
Old: 
```
Configure the file integrity tool to run automatically on the system at
least weekly and to notify designated personnel if baseline configurations are
changed in an unauthorized manner. The AIDE tool can be configured to email
designated personnel with the use of the cron system.

    The following example output is generic. It will set cron to run AIDE daily
and to send email at the completion of the analysis.

    $ sudo more /etc/cron.daily/aide

    #!/bin/bash

    /usr/sbin/aide --check | /bin/mail -s "$HOSTNAME - Daily aide integrity
check run" root@sysname.mil

```
New:
```
Configure the file integrity tool to run automatically on the system at least weekly and to notify designated personnel if baseline configurations are changed in an unauthorized manner. The AIDE tool can be configured to email designated personnel with the use of the cron system.

The following example output is generic. It will set cron to run AIDE daily and to send email at the completion of the analysis. 

     $ sudo more /etc/cron.daily/aide

     #!/bin/bash

     /usr/sbin/aide --check | /bin/mail -s "$HOSTNAME - Daily AIDE integrity check run" root@example_server_name.mil

Note: Per requirement RHEL-08-010358, the "mailx" package must be installed on the system to enable email functionality.

```
---
SV-230266:
Old: 
```
Configure the operating system to disable kernel image loading.

    Add or edit the following line in a system configuration file in the
"/etc/sysctl.d/" directory:

    kernel.kexec_load_disabled = 1

    Load settings from all system configuration files with the following
command:

    $ sudo sysctl --system

```
New:
```
Configure the operating system to disable kernel image loading.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

kernel.kexec_load_disabled = 1

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system

```
---
SV-230267:
Old: 
```
Configure the operating system to enable DAC on symlinks.

    Add or edit the following line in a system configuration file in the
"/etc/sysctl.d/" directory:

    fs.protected_symlinks = 1

    Load settings from all system configuration files with the following
command:

    $ sudo sysctl --system

```
New:
```
Configure the operating system to enable DAC on symlinks.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

fs.protected_symlinks = 1

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system

```
---
SV-230268:
Old: 
```
Configure the operating system to enable DAC on hardlinks.

    Add or edit the following line in a system configuration file in the
"/etc/sysctl.d/" directory:

    fs.protected_hardlinks = 1

    Load settings from all system configuration files with the following
command:

    $ sudo sysctl --system

```
New:
```
Configure the operating system to enable DAC on hardlinks.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

fs.protected_hardlinks = 1

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system

```
---
SV-230269:
Old: 
```
Configure the operating system to restrict access to the kernel message
buffer.

    Add or edit the following line in a system configuration file in the
"/etc/sysctl.d/" directory:

    kernel.dmesg_restrict = 1

    Load settings from all system configuration files with the following
command:

    $ sudo sysctl --system

```
New:
```
Configure the operating system to restrict access to the kernel message buffer.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

kernel.dmesg_restrict = 1

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system

```
---
SV-230270:
Old: 
```
Configure the operating system to prevent kernel profiling by unprivileged
users.

    Add or edit the following line in a system configuration file in the
"/etc/sysctl.d/" directory:

    kernel.perf_event_paranoid = 2

    Load settings from all system configuration files with the following
command:

    $ sudo sysctl --system

```
New:
```
Configure the operating system to prevent kernel profiling by unprivileged users.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

kernel.perf_event_paranoid = 2

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system

```
---
SV-230280:
Old: 
```
Configure the operating system to implement virtual address space
randomization.

    Set the system to the required kernel parameter by adding the following
line to "/etc/sysctl.d/*.conf"(or modify the line to have the required value):

    kernel.randomize_va_space=2

    Issue the following command to make the changes take effect:

    $ sudo sysctl --system

```
New:
```
Configure the operating system to implement virtual address space randomization.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

kernel.randomize_va_space=2

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Issue the following command to make the changes take effect:

$ sudo sysctl --system

```
---
SV-230311:
Old: 
```
Configure RHEL 8 to disable storing core dumps by adding the following line
to a file in the "/etc/sysctl.d" directory:

    kernel.core_pattern = |/bin/false

    The system configuration files need to be reloaded for the changes to take
effect. To reload the contents of the files, run the following command:

    $ sudo sysctl --system

```
New:
```
Configure RHEL 8 to disable storing core dumps.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

kernel.core_pattern = |/bin/false

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system

```
---
SV-230312:
Old: 
```
Configure the system to disable the systemd-coredump.socket with the
following command:

    $ sudo systemctl mask systemd-coredump.socket

    Created symlink /etc/systemd/system/systemd-coredump.socket -> /dev/null

    Reload the daemon for this change to take effect.

    $ sudo systemctl daemon-reload

```
New:
```
Configure the system to disable the systemd-coredump.socket with the following commands:

$ sudo systemctl disable --now systemd-coredump.socket

$ sudo systemctl mask systemd-coredump.socket

Created symlink /etc/systemd/system/systemd-coredump.socket -> /dev/null

Reload the daemon for this change to take effect.

$ sudo systemctl daemon-reload

```
---
SV-230328:
Old: 
```
Migrate the "/home" directory onto a separate file
system/partition.

```
New:
```
Migrate the "/home" directory onto a separate file system.

```
---
SV-230348:
Old: 
```
Configure the operating system to enable a user to initiate a session lock
via tmux.

    Create a global configuration file "/etc/tmux.conf" and add the following
line:

    set -g lock-command vlock

```
New:
```
Configure the operating system to enable a user to manually initiate a session lock via tmux. This configuration binds the uppercase letter "X" to manually initiate a session lock after the prefix key "Ctrl + b" has been sent. The complete key sequence is thus "Ctrl + b" then "Shift + x" to lock tmux.

Create a global configuration file "/etc/tmux.conf" and add the following lines:

     set -g lock-command vlock
     bind X lock-session

Reload tmux configuration to take effect. This can be performed in tmux while it is running:

     $ tmux source-file /etc/tmux.conf

```
---
SV-230349:
Old: 
```
Configure the operating system to initialize the tmux terminal multiplexer
as each shell is called by adding the following line to the end of the
"/etc/bashrc" configuration file:

    [ -n "$PS1" -a -z "$TMUX" ] && exec tmux

    This setting will take effect at next logon.

```
New:
```
Configure the operating system to initialize the tmux terminal multiplexer as each shell is called by adding the following lines to a custom.sh shell script in the /etc/profile.d/ directory:

if [ "$PS1" ]; then
parent=$(ps -o ppid= -p $$)
name=$(ps -o comm= -p $parent)
case "$name" in (sshd|login) tmux ;; esac
fi

This setting will take effect at next logon.

```
---
SV-230355:
Old: 
```
Configure the operating system to map the authenticated identity to the
user or group account by adding or modifying the certmap section of the
"/etc/sssd/sssd.conf file based on the following example:

    [certmap/testing.test/rule_name]
    matchrule =<SAN>.*EDIPI@mil
    maprule = (userCertificate;binary={cert!bin})
    dmains = testing.test

    The "sssd" service must be restarted for the changes to take effect. To
restart the "sssd" service, run the following command:

    $ sudo systemctl restart sssd.service

```
New:
```
Configure the operating system to map the authenticated identity to the user or group account by adding or modifying the certmap section of the "/etc/sssd/sssd.conf file based on the following example:

[certmap/testing.test/rule_name]
matchrule =<SAN>.*EDIPI@mil
maprule = (userCertificate;binary={cert!bin})
domains = testing.test

The "sssd" service must be restarted for the changes to take effect. To restart the "sssd" service, run the following command:

$ sudo systemctl restart sssd.service

```
---
SV-230357:
Old: 
```
Configure the operating system to enforce password complexity by requiring
that at least one uppercase character be used by setting the "ucredit" option.

    Add the following line to /etc/security/pwquality.conf (or modify the line
to have the required value):

    ucredit = -1

```
New:
```
Configure the operating system to enforce password complexity by requiring that at least one uppercase character be used by setting the "ucredit" option.

Add the following line to /etc/security/pwquality.conf (or modify the line to have the required value):

ucredit = -1

Remove any configurations that conflict with the above value.

```
---
SV-230358:
Old: 
```
Configure the operating system to enforce password complexity by requiring
that at least one lower-case character be used by setting the "lcredit"
option.

    Add the following line to /etc/security/pwquality.conf (or modify the line
to have the required value):

    lcredit = -1

```
New:
```
Configure the operating system to enforce password complexity by requiring that at least one lower-case character be used by setting the "lcredit" option.

Add the following line to /etc/security/pwquality.conf (or modify the line to have the required value):

lcredit = -1

Remove any configurations that conflict with the above value.

```
---
SV-230359:
Old: 
```
Configure the operating system to enforce password complexity by requiring
that at least one numeric character be used by setting the "dcredit" option.

    Add the following line to /etc/security/pwquality.conf (or modify the line
to have the required value):

    dcredit = -1

```
New:
```
Configure the operating system to enforce password complexity by requiring that at least one numeric character be used by setting the "dcredit" option.

Add the following line to /etc/security/pwquality.conf (or modify the line to have the required value):

dcredit = -1

Remove any configurations that conflict with the above value.

```
---
SV-230360:
Old: 
```
Configure the operating system to require the change of the number of
repeating characters of the same character class when passwords are changed by
setting the "maxclassrepeat" option.

    Add the following line to "/etc/security/pwquality.conf" conf (or modify
the line to have the required value):

    maxclassrepeat = 4

```
New:
```
Configure the operating system to require the change of the number of repeating characters of the same character class when passwords are changed by setting the "maxclassrepeat" option.

Add the following line to "/etc/security/pwquality.conf" conf (or modify the line to have the required value):

maxclassrepeat = 4

Remove any configurations that conflict with the above value.

```
---
SV-230361:
Old: 
```
Configure the operating system to require the change of the number of
repeating consecutive characters when passwords are changed by setting the
"maxrepeat" option.

    Add the following line to "/etc/security/pwquality.conf conf" (or modify
the line to have the required value):

    maxrepeat = 3

```
New:
```
Configure the operating system to require the change of the number of repeating consecutive characters when passwords are changed by setting the "maxrepeat" option.

Add the following line to "/etc/security/pwquality.conf conf" (or modify the line to have the required value):

maxrepeat = 3

Remove any configurations that conflict with the above value.

```
---
SV-230362:
Old: 
```
Configure the operating system to require the change of at least four
character classes when passwords are changed by setting the "minclass" option.

    Add the following line to "/etc/security/pwquality.conf conf" (or modify
the line to have the required value):

    minclass = 4

```
New:
```
Configure the operating system to require the change of at least four character classes when passwords are changed by setting the "minclass" option.

Add the following line to "/etc/security/pwquality.conf conf" (or modify the line to have the required value):

minclass = 4

Remove any configurations that conflict with the above value.

```
---
SV-230363:
Old: 
```
Configure the operating system to require the change of at least eight of
the total number of characters when passwords are changed by setting the
"difok" option.

    Add the following line to "/etc/security/pwquality.conf" (or modify the
line to have the required value):

    difok = 8

```
New:
```
Configure the operating system to require the change of at least eight of the total number of characters when passwords are changed by setting the "difok" option.

Add the following line to "/etc/security/pwquality.conf" (or modify the line to have the required value):

difok = 8

Remove any configurations that conflict with the above value.

```
---
SV-230368:
Old: 
```
Configure the operating system to prohibit password reuse for a minimum of
five generations.

    Add the following line in "/etc/pam.d/system-auth" and
"/etc/pam.d/password-auth" (or modify the line to have the required value):

    password required pam_pwhistory.so use_authtok remember=5 retry=3

```
New:
```
Configure the operating system in the password-auth file to prohibit password reuse for a minimum of five generations.

Add the following line in "/etc/pam.d/password-auth" (or modify the line to have the required value):

     password requisite pam_pwhistory.so use_authtok remember=5 retry=3

```
---
SV-230369:
Old: 
```
Configure operating system to enforce a minimum 15-character password
length.

    Add the following line to "/etc/security/pwquality.conf" (or modify the
line to have the required value):

    minlen = 15

```
New:
```
Configure operating system to enforce a minimum 15-character password length.

Add the following line to "/etc/security/pwquality.conf" (or modify the line to have the required value):

minlen = 15

Remove any configurations that conflict with the above value.

```
---
SV-230374:
Old: 
```
If an emergency account must be created, configure the system to terminate
the account after 72 hours with the following command to set an expiration date
for the account. Substitute "system_account_name" with the account to be
created.

    $ sudo chage -E `date -d "+3 days" +%Y-%m-%d` system_account_name

    The automatic expiration or disabling time period may be extended as needed
until the crisis is resolved.

```
New:
```
Configure the operating system to expire temporary accounts after 72 hours with the following command:

     $ sudo chage -E $(date -d +3days +%Y-%m-%d) <temporary_account_name>

```
---
SV-230375:
Old: 
```
Configure the operating system to enforce password complexity by requiring
that at least one special character be used by setting the "ocredit" option.

    Add the following line to /etc/security/pwquality.conf (or modify the line
to have the required value):

    ocredit = -1

```
New:
```
Configure the operating system to enforce password complexity by requiring that at least one special character be used by setting the "ocredit" option.

Add the following line to /etc/security/pwquality.conf (or modify the line to have the required value):

ocredit = -1

Remove any configurations that conflict with the above value.

```
---
SV-230377:
Old: 
```
Configure RHEL 8 to prevent the use of dictionary words for passwords.

    Add or update the following line in the "/etc/security/pwquality.conf"
file or a configuration file in the /etc/pwquality.conf.d/ directory to contain
the "dictcheck" parameter:

    dictcheck=1

```
New:
```
Configure RHEL 8 to prevent the use of dictionary words for passwords.

Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the /etc/pwquality.conf.d/ directory to contain the "dictcheck" parameter:

dictcheck=1

Remove any configurations that conflict with the above value.

```
---
SV-230385:
Old: 
```
Configure the operating system to define default permissions for all
authenticated users in such a way that the user can only read and modify their
own files.

    Add or edit the lines for the "UMASK" parameter in the "/etc/bashrc"
and "etc/csh.cshrc" files to "077":

    UMASK 077

```
New:
```
Configure the operating system to define default permissions for all authenticated users in such a way that the user can only read and modify their own files.

Add or edit the lines for the "UMASK" parameter in the "/etc/bashrc", "/etc/csh.cshrc" and "/etc/profile"files to "077":

UMASK 077

```
---
SV-230396:
Old: 
```
Configure the audit log to be protected from unauthorized read access by
configuring the log group in the /etc/audit/auditd.conf file:

    log_group = root

```
New:
```
Configure the audit log to be protected from unauthorized read access by setting the correct permissive mode with the following command: 
 
$ sudo chmod 0600 /var/log/audit/audit.log

```
---
SV-230413:
Old: 
```
Configure RHEL 8 to audit the execution of the "lremovexattr" system
call, by adding or updating the following lines to
"/etc/audit/rules.d/audit.rules":

    -a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=unset -k
perm_mod
    -a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=unset -k
perm_mod

    -a always,exit -F arch=b32 -S lremovexattr -F auid=0 -k perm_mod
    -a always,exit -F arch=b64 -S lremovexattr -F auid=0 -k perm_mod

    The audit daemon must be restarted for the changes to take effect.

```
New:
```
Configure RHEL 8 to audit the execution of the "setxattr", "fsetxattr", "lsetxattr", "removexattr", "fremovexattr", and "lremovexattr" system calls by adding or updating the following lines to "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod

-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod
-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod

The audit daemon must be restarted for the changes to take effect.

```
---
SV-230438:
Old: 
```
Configure the audit system to generate an audit event for any
successful/unsuccessful use of the "init_module" command by adding or
updating the following rules in the "/etc/audit/rules.d/audit.rules" file:

    -a always,exit -F arch=b32 -S init_module -F auid>=1000 -F auid!=unset -k
module_chng
    -a always,exit -F arch=b64 -S init_module -F auid>=1000 -F auid!=unset -k
module_chng

    The audit daemon must be restarted for the changes to take effect.

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of the "init_module" and "finit_module" system calls by adding or updating the following rules in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng
-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng

The audit daemon must be restarted for the changes to take effect.

```
---
SV-230439:
Old: 
```
Configure the audit system to generate an audit event for any
successful/unsuccessful use of the "rename" command by adding or updating the
following rules in the "/etc/audit/rules.d/audit.rules" file:

    -a always,exit -F arch=b32 -S rename -F auid>=1000 -F auid!=unset -k delete
    -a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=unset -k delete

    The audit daemon must be restarted for the changes to take effect.

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of the "rename", "unlink", "rmdir", "renameat", and "unlinkat" system calls by adding or updating the following rules in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F arch=b32 -S rename,unlink,rmdir,renameat,unlinkat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b64 -S rename,unlink,rmdir,renameat,unlinkat -F auid>=1000 -F auid!=unset -k delete

The audit daemon must be restarted for the changes to take effect.

```
---
SV-230449:
Old: 
```
Configure the audit system to generate an audit event for any
successful/unsuccessful use of the "truncate" command by adding or updating
the following rules in the "/etc/audit/rules.d/audit.rules" file:

    -a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F
auid!=unset -k perm_access
    -a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F
auid!=unset -k perm_access

    -a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F
auid!=unset -k perm_access
    -a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F
auid!=unset -k perm_access

    The audit daemon must be restarted for the changes to take effect.

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of the "truncate", "ftruncate", "creat", "open", "openat", and "open_by_handle_at" system calls by adding or updating the following rules in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F arch=b32 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access
-a always,exit -F arch=b64 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access

-a always,exit -F arch=b32 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access
-a always,exit -F arch=b64 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access

The audit daemon must be restarted for the changes to take effect.

```
---
SV-230455:
Old: 
```
Configure the audit system to generate an audit event for any
successful/unsuccessful use of the "chown" command by adding or updating the
following line to "/etc/audit/rules.d/audit.rules":

    -a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=unset -k perm_mod
    -a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=unset -k perm_mod

    The audit daemon must be restarted for the changes to take effect.

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of the "chown", "fchown", "fchownat", and "lchown" system calls by adding or updating the following line to "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod

The audit daemon must be restarted for the changes to take effect.

```
---
SV-230456:
Old: 
```
Configure the audit system to generate an audit event for any
successful/unsuccessful use of the "chmod" command by adding or updating the
following line to "/etc/audit/rules.d/audit.rules":

    -a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=unset -k perm_mod
    -a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=unset -k perm_mod

    The audit daemon must be restarted for the changes to take effect.

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of the "chmod", "fchmod", and "fchmodat" syscalls by adding or updating the following line to "/etc/audit/rules.d/audit.rules": 

-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod

The audit daemon must be restarted for the changes to take effect.

```
---
SV-230479:
Old: 
```
Configure the operating system to off-load audit records onto a different
system or media from the system being audited by specifying the remote logging
server in "/etc/rsyslog.conf" or "/etc/rsyslog.d/[customfile].conf" with
the name or IP address of the log aggregation server.

    *.* @@[remoteloggingserver]:[port]

```
New:
```
Configure the operating system to offload audit records onto a different system or media from the system being audited by specifying the remote logging server in "/etc/rsyslog.conf" or "/etc/rsyslog.d/[customfile].conf" with the name or IP address of the log aggregation server.

For UDP:
     *.* @[logaggregationserver.example.mil]:[port]

For TCP: 
     *.* @@[logaggregationserver.example.mil]:[port]

```
---
SV-230485:
Old: 
```
Configure the operating system to disable the chrony daemon from acting as
a server by adding/modifying the following line in the /etc/chrony.conf file.

    port 0

```
New:
```
Configure the operating system to disable the chrony daemon from acting as a server by adding or modifying the following line in the "/etc/chrony.conf" file:

     port 0

```
---
SV-230486:
Old: 
```
Configure the operating system disable network management of the chrony
daemon by adding/modifying the following line in the /etc/chrony.conf file.

    cmdport 0

```
New:
```
Configure the operating system disable network management of the chrony daemon by adding or modifying the following line in the "/etc/chrony.conf" file.

     cmdport 0

```
---
SV-230503:
Old: 
```
Configure the operating system to disable the ability to use the USB
Storage kernel module.

    Create a file under "/etc/modprobe.d" with the following command:

    $ sudo touch /etc/modprobe.d/usb-storage.conf

    Add the following line to the created file:

    install usb-storage /bin/true

    Configure the operating system to disable the ability to use USB mass
storage devices.

    $ sudo vi /etc/modprobe.d/blacklist.conf

    Add or update the line:

    blacklist usb-storage

```
New:
```
Configure the operating system to disable the ability to use the USB Storage kernel module and the ability to use USB mass storage devices.

Add or update the following lines in the file "/etc/modprobe.d/blacklist.conf":

install usb-storage /bin/true
blacklist usb-storage

Reboot the system for the settings to take effect.

```
---
SV-230504:
Old: 
```
Configure the "firewalld" daemon to employ a deny-all, allow-by-exception
with the following commands:

    $ sudo firewall-cmd --permanent --new-zone=[custom]

    $ sudo cp /usr/lib/firewalld/zones/drop.xml
/etc/firewalld/zones/[custom].xml

    This will provide a clean configuration file to work with that employs a
deny-all approach. Next, add the exceptions that are required for mission
functionality.

    $ sudo firewall-cmd --set-default-zone=[custom]

    Note: This is a runtime and permanent change.

```
New:
```
Configure the "firewalld" daemon to employ a deny-all, allow-by-exception with the following commands:

$ sudo firewall-cmd --permanent --new-zone=[custom]

$ sudo cp /usr/lib/firewalld/zones/drop.xml /etc/firewalld/zones/[custom].xml

This will provide a clean configuration file to work with that employs a deny-all approach. Note: Add the exceptions that are required for mission functionality and update the short title in the xml file to match the [custom] zone name.

Reload the firewall rules to make the new [custom] zone available to load:
$ sudo firewall-cmd --reload 

Set the default zone to the new [custom] zone:
$ sudo firewall-cmd --set-default-zone=[custom]

Note: This is a runtime and permanent change.
Add any interfaces to the new [custom] zone:
$ sudo firewall-cmd --permanent --zone=[custom] --change-interface=ens33

Reload the firewall rules for changes to take effect:
$ sudo firewall-cmd --reload

```
---
SV-230507:
Old: 
```
Configure the operating system to disable the Bluetooth adapter when not in
use.

    Build or modify the "/etc/modprobe.d/bluetooth.conf" file with the
following line:

    install bluetooth /bin/true

    Reboot the system for the settings to take effect.

```
New:
```
Configure the operating system to disable the Bluetooth adapter when not in use.

Build or modify the "/etc/modprobe.d/bluetooth.conf" file with the following line:

install bluetooth /bin/true

Disable the ability to use the Bluetooth kernel module. 
 
$ sudo vi /etc/modprobe.d/blacklist.conf 
 
Add or update the line: 
 
blacklist bluetooth

Reboot the system for the settings to take effect.

```
---
SV-230520:
Old: 
```
Configure the system so that /var/tmp is mounted with the "nodev" option
by adding /modifying the /etc/fstab with the following line:

    /dev/mapper/rhel-var-log-audit /var/tmp xfs defaults,nodev,nosuid,noexec 0 0

```
New:
```
Configure the system so that /var/tmp is mounted with the "nodev" option by adding /modifying the /etc/fstab with the following line:

/dev/mapper/rhel-var-tmp /var/tmp xfs defaults,nodev,nosuid,noexec 0 0

```
---
SV-230521:
Old: 
```
Configure the system so that /var/tmp is mounted with the "nosuid" option
by adding /modifying the /etc/fstab with the following line:

    /dev/mapper/rhel-var-log-audit /var/tmp xfs defaults,nodev,nosuid,noexec 0 0

```
New:
```
Configure the system so that /var/tmp is mounted with the "nosuid" option by adding /modifying the /etc/fstab with the following line:

/dev/mapper/rhel-var-tmp /var/tmp xfs defaults,nodev,nosuid,noexec 0 0

```
---
SV-230522:
Old: 
```
Configure the system so that /var/tmp is mounted with the "noexec" option
by adding /modifying the /etc/fstab with the following line:

    /dev/mapper/rhel-var-log-audit /var/tmp xfs defaults,nodev,nosuid,noexec 0 0

```
New:
```
Configure the system so that /var/tmp is mounted with the "noexec" option by adding /modifying the /etc/fstab with the following line:

/dev/mapper/rhel-var-tmp /var/tmp xfs defaults,nodev,nosuid,noexec 0 0

```
---
SV-230529:
Old: 
```
Configure the system to disable the Ctrl-Alt-Delete sequence for the
command line with the following command:

    $ sudo systemctl mask ctrl-alt-del.target

    Created symlink /etc/systemd/system/ctrl-alt-del.target -> /dev/null

    Reload the daemon for this change to take effect.

    $ sudo systemctl daemon-reload

```
New:
```
Configure the system to disable the Ctrl-Alt-Delete sequence for the command line with the following commands:

$ sudo systemctl disable ctrl-alt-del.target

$ sudo systemctl mask ctrl-alt-del.target

Created symlink /etc/systemd/system/ctrl-alt-del.target -> /dev/null

Reload the daemon for this change to take effect.

$ sudo systemctl daemon-reload

```
---
SV-230535:
Old: 
```
Configure RHEL 8 to prevent IPv6 ICMP redirect messages from being accepted
with the following command:

    $ sudo sysctl -w net.ipv6.conf.default.accept_redirects=0

    If "0" is not the system's default value then add or update the following
line in the appropriate file under "/etc/sysctl.d":

    net.ipv6.conf.default.accept_redirects=0

```
New:
```
Configure RHEL 8 to prevent IPv6 ICMP redirect messages from being accepted.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv6.conf.default.accept_redirects = 0

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system

```
---
SV-230536:
Old: 
```
Configure RHEL 8 to not allow interfaces to perform IPv4 ICMP redirects
with the following command:

    $ sudo sysctl -w net.ipv4.conf.all.send_redirects=0

    If "0" is not the system's default value then add or update the following
line in the appropriate file under "/etc/sysctl.d":

    net.ipv4.conf.all.send_redirects=0

```
New:
```
Configure RHEL 8 to not allow interfaces to perform IPv4 ICMP redirects.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.all.send_redirects=0

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system

```
---
SV-230537:
Old: 
```
Configure RHEL 8 to not respond to IPv4 ICMP echoes sent to a broadcast
address with the following command:

    $ sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1

    If "1" is not the system's default value then add or update the following
line in the appropriate file under "/etc/sysctl.d":

    net.ipv4.icmp_echo_ignore_broadcasts=1

```
New:
```
Configure RHEL 8 to not respond to IPv4 ICMP echoes sent to a broadcast address.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.icmp_echo_ignore_broadcasts=1

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system

```
---
SV-230538:
Old: 
```
Configure RHEL 8 to not forward IPv6 source-routed packets with the
following command:

    $ sudo sysctl -w net.ipv6.conf.all.accept_source_route=0

    If "0" is not the system's all value then add or update the following
line in the appropriate file under "/etc/sysctl.d":

    net.ipv6.conf.all.accept_source_route=0

```
New:
```
Configure RHEL 8 to not forward IPv6 source-routed packets.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv6.conf.all.accept_source_route=0

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system

```
---
SV-230539:
Old: 
```
Configure RHEL 8 to not forward IPv6 source-routed packets by default with
the following command:

    $ sudo sysctl -w net.ipv6.conf.default.accept_source_route=0

    If "0" is not the system's default value then add or update the following
line in the appropriate file under "/etc/sysctl.d":

    net.ipv6.conf.default.accept_source_route=0

```
New:
```
Configure RHEL 8 to not forward IPv6 source-routed packets by default.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv6.conf.default.accept_source_route=0

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system

```
---
SV-230540:
Old: 
```
Configure RHEL 8 to not allow packet forwarding, unless the system is a
router with the following commands:

    $ sudo sysctl -w net.ipv4.ip_forward=0

    $ sudo sysctl -w net.ipv6.conf.all.forwarding=0

    If "0" is not the system's default value then add or update the following
lines in the appropriate file under "/etc/sysctl.d":

    net.ipv4.ip_forward=0

    net.ipv6.conf.all.forwarding=0

```
New:
```
Configure RHEL 8 to not allow IPv6 packet forwarding, unless the system is a router.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv6.conf.all.forwarding=0

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system

```
---
SV-230541:
Old: 
```
Configure RHEL 8 to not accept router advertisements on all IPv6 interfaces
unless the system is a router with the following commands:

    $ sudo sysctl -w net.ipv6.conf.all.accept_ra=0

    If "0" is not the system's default value then add or update the following
lines in the appropriate file under "/etc/sysctl.d":

    net.ipv6.conf.all.accept_ra=0

```
New:
```
Configure RHEL 8 to not accept router advertisements on all IPv6 interfaces unless the system is a router.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv6.conf.all.accept_ra=0

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system

```
---
SV-230542:
Old: 
```
Configure RHEL 8 to not accept router advertisements on all IPv6 interfaces
by default unless the system is a router with the following commands:

    $ sudo sysctl -w net.ipv6.conf.default.accept_ra=0

    If "0" is not the system's default value then add or update the following
lines in the appropriate file under "/etc/sysctl.d":

    net.ipv6.conf.default.accept_ra=0

```
New:
```
Configure RHEL 8 to not accept router advertisements on all IPv6 interfaces by default unless the system is a router.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv6.conf.default.accept_ra=0

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system

```
---
SV-230543:
Old: 
```
Configure RHEL 8 to not allow interfaces to perform Internet Protocol
version 4 (IPv4) ICMP redirects by default with the following command:

    $ sudo sysctl -w net.ipv4.conf.default.send_redirects=0

    If "0" is not the system's default value then add or update the following
line in the appropriate file under "/etc/sysctl.d":

    net.ipv4.conf.default.send_redirects=0

```
New:
```
Configure RHEL 8 to not allow interfaces to perform Internet Protocol version 4 (IPv4) ICMP redirects by default.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.default.send_redirects = 0

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system

```
---
SV-230544:
Old: 
```
Configure RHEL 8 to ignore IPv6 ICMP redirect messages with the following
command:

    $ sudo sysctl -w net.ipv6.conf.all.accept_redirects=0

    If "0" is not the system's default value then add or update the following
line in the appropriate file under "/etc/sysctl.d":

    net.ipv6.conf.all.accept_redirects = 0

```
New:
```
Configure RHEL 8 to ignore IPv6 ICMP redirect messages.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv6.conf.all.accept_redirects = 0

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system

```
---
SV-230545:
Old: 
```
Configure RHEL 8 to prevent privilege escalation thru the kernel by
disabling access to the bpf syscall by adding the following line to a file in
the "/etc/sysctl.d" directory:

    kernel.unprivileged_bpf_disabled = 1

    The system configuration files need to be reloaded for the changes to take
effect. To reload the contents of the files, run the following command:

    $ sudo sysctl --system

```
New:
```
Configure RHEL 8 to prevent privilege escalation thru the kernel by disabling access to the bpf syscall by adding the following line to a file, in the "/etc/sysctl.d" directory:

kernel.unprivileged_bpf_disabled = 1

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system

```
---
SV-230546:
Old: 
```
Configure RHEL 8 to restrict usage of ptrace to descendant processes by
adding the following line to a file in the "/etc/sysctl.d" directory:

    kernel.yama.ptrace_scope = 1

    The system configuration files need to be reloaded for the changes to take
effect. To reload the contents of the files, run the following command:

    $ sudo sysctl --system

```
New:
```
Configure RHEL 8 to restrict usage of ptrace to descendant processes by adding the following line to a file, in the "/etc/sysctl.d" directory:

kernel.yama.ptrace_scope = 1

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system

```
---
SV-230547:
Old: 
```
Configure RHEL 8 to restrict exposed kernel pointer addresses access by
adding the following line to a file in the "/etc/sysctl.d" directory:

    kernel.kptr_restrict = 1

    The system configuration files need to be reloaded for the changes to take
effect. To reload the contents of the files, run the following command:

    $ sudo sysctl --system

```
New:
```
Configure RHEL 8 to restrict exposed kernel pointer addresses access by adding the following line to a file, in the "/etc/sysctl.d" directory:

kernel.kptr_restrict = 1

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system

```
---
SV-230548:
Old: 
```
Configure RHEL 8 to disable the use of user namespaces by adding the
following line to a file in the "/etc/sysctl.d" directory:

    Note: User namespaces are used primarily for Linux containers.  If
containers are in use, this requirement is not applicable.

    user.max_user_namespaces = 0

    The system configuration files need to be reloaded for the changes to take
effect. To reload the contents of the files, run the following command:

    $ sudo sysctl --system

```
New:
```
Configure RHEL 8 to disable the use of user namespaces by adding the following line to a file, in the "/etc/sysctl.d" directory:

Note: User namespaces are used primarily for Linux containers. If containers are in use, this requirement is not applicable. 

user.max_user_namespaces = 0

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system

```
---
SV-230549:
Old: 
```
Configure RHEL 8 to use reverse path filtering on all IPv4 interfaces by
adding the following line to a file in the "/etc/sysctl.d" directory:

    net.ipv4.conf.all.rp_filter = 1

    The system configuration files need to be reloaded for the changes to take
effect. To reload the contents of the files, run the following command:

    $ sudo sysctl --system

```
New:
```
Configure RHEL 8 to use reverse path filtering on all IPv4 interfaces by adding the following line to a file, in the "/etc/sysctl.d" directory:

net.ipv4.conf.all.rp_filter = 1

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system

```
---
SV-230553:
Old: 
```
Document the requirement for a graphical user interface with the ISSO or
reinstall the operating system without the graphical user interface. If
reinstallation is not feasible, then continue with the following procedure:

    Open an SSH session and enter the following commands:

    $ sudo systemctl set-default multi-user.target

    $ sudo yum remove xorg-x11-server-Xorg xorg-x11-server-common
xorg-x11-server-utils xorg-x11-server-Xwayland

    A reboot is required for the changes to take effect.

```
New:
```
Document the requirement for a graphical user interface with the ISSO or reinstall the operating system without the graphical user interface. If reinstallation is not feasible, then continue with the following procedure:

Open an SSH session and enter the following commands:

$ sudo yum remove xorg-x11-server-Xorg xorg-x11-server-common xorg-x11-server-utils xorg-x11-server-Xwayland

A reboot is required for the changes to take effect.

```
---
SV-237642:
Old: 
```
Define the following in the Defaults section of the /etc/sudoers file or a
configuration file in the /etc/sudoers.d/ directory:
    Defaults !targetpw
    Defaults !rootpw
    Defaults !runaspw

```
New:
```
Define the following in the Defaults section of the /etc/sudoers file or a configuration file in the /etc/sudoers.d/ directory:
     Defaults !targetpw
     Defaults !rootpw
     Defaults !runaspw

Remove any configurations that conflict with the above from the following locations: 
     /etc/sudoers
     /etc/sudoers.d/

```
---
SV-237643:
Old: 
```
Configure the "sudo" command to require re-authentication.
    Edit the /etc/sudoers file:
    $ sudo visudo

    Add or modify the following line:
    Defaults timestamp_timeout=[value]
    Note: The "[value]" must be a number that is greater than or equal to
"0".

```
New:
```
Configure the "sudo" command to require re-authentication.
Edit the /etc/sudoers file:
$ sudo visudo

Add or modify the following line:
Defaults timestamp_timeout=[value]
Note: The "[value]" must be a number that is greater than or equal to "0".

Remove any duplicate or conflicting lines from /etc/sudoers and /etc/sudoers.d/ files.

```
---
SV-244524:
Old: 
```
Configure RHEL 8 to use a FIPS 140-2 approved cryptographic hashing
algorithm for system authentication.

    Edit/modify the following line in the "/etc/pam.d/system-auth" file to
include the sha512 option for pam_unix.so:

    password sufficient pam_unix.so sha512 rounds=5000

```
New:
```
Configure RHEL 8 to use a FIPS 140-2 approved cryptographic hashing algorithm for system authentication.

Edit/modify the following line in the "/etc/pam.d/system-auth" file to include the sha512 option for pam_unix.so:

password sufficient pam_unix.so sha512

```
---
SV-244525:
Old: 
```
Configure RHEL 8 to automatically terminate all network connections
associated with SSH traffic at the end of a session or after 10 minutes of
inactivity.

    Modify or append the following lines in the "/etc/ssh/sshd_config" file:

    ClientAliveInterval 600

    In order for the changes to take effect, the SSH daemon must be restarted.

    $ sudo systemctl restart sshd.service

```
New:
```
Note: This setting must be applied in conjunction with RHEL-08-010200 to function correctly.

Configure the SSH server to terminate a user session automatically after the SSH client has been unresponsive for 10 minutes.

Modify or append the following lines in the "/etc/ssh/sshd_config" file:

     ClientAliveInterval 600

For the changes to take effect, the SSH daemon must be restarted.

     $ sudo systemctl restart sshd.service

```
---
SV-244526:
Old: 
```
Configure the RHEL 8 SSH daemon to use system-wide crypto policies by
adding the following line to /etc/sysconfig/sshd:

    # crypto_policy=

    A reboot is required for the changes to take effect.

```
New:
```
Configure the RHEL 8 SSH daemon to use system-wide crypto policies by adding the following line to /etc/sysconfig/sshd:

# CRYPTO_POLICY=

A reboot is required for the changes to take effect.

```
---
SV-244550:
Old: 
```
Configure RHEL 8 to prevent IPv4 ICMP redirect messages from being accepted
with the following command:

    $ sudo sysctl -w net.ipv4.conf.default.accept_redirects=0

    If "0" is not the system's default value then add or update the following
line in the appropriate file under "/etc/sysctl.d":

    net.ipv4.conf.default.accept_redirects=0

```
New:
```
Configure RHEL 8 to prevent IPv4 ICMP redirect messages from being accepted.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.default.accept_redirects = 0

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system

```
---
SV-244551:
Old: 
```
Configure RHEL 8 to not forward IPv4 source-routed packets with the
following command:

    $ sudo sysctl -w net.ipv4.conf.all.accept_source_route=0

    If "0" is not the system's all value then add or update the following
line in the appropriate file under "/etc/sysctl.d":

    net.ipv4.conf.all.accept_source_route=0

```
New:
```
Configure RHEL 8 to not forward IPv4 source-routed packets.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.all.accept_source_route=0

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system

```
---
SV-244552:
Old: 
```
Configure RHEL 8 to not forward IPv4 source-routed packets by default with
the following command:

    $ sudo sysctl -w net.ipv4.conf.default.accept_source_route=0

    If "0" is not the system's default value then add or update the following
line in the appropriate file under "/etc/sysctl.d":

    net.ipv4.conf.default.accept_source_route=0

```
New:
```
Configure RHEL 8 to not forward IPv4 source-routed packets by default.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.default.accept_source_route=0

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system

```
---
SV-244553:
Old: 
```
Configure RHEL 8 to ignore IPv4 ICMP redirect messages with the following
command:

    $ sudo sysctl -w net.ipv4.conf.all.accept_redirects=0

    If "0" is not the system's default value then add or update the following
line in the appropriate file under "/etc/sysctl.d":

    net.ipv4.conf.all.accept_redirects = 0

```
New:
```
Configure RHEL 8 to ignore IPv4 ICMP redirect messages.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.all.accept_redirects = 0

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system

```
---
SV-244554:
Old: 
```
Configure RHEL 8 to enable hardening for the BPF JIT compiler by adding the
following line to a file in the "/etc/sysctl.d" directory:

    net.core.bpf_jit_harden = 2

    The system configuration files need to be reloaded for the changes to take
effect. To reload the contents of the files, run the following command:

    $ sudo sysctl --system

```
New:
```
Configure RHEL 8 to enable hardening for the BPF JIT compiler by adding the following line to a file, in the "/etc/sysctl.d" directory:

net.core.bpf_jit_harden = 2

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system

```
---
</details>

### Updated Impacts
<details open>
  <summary>Click to expand.</summary>
SV-230226:
Old: 0
New: 0.5
---
SV-230234:
Old: 0
New: 0.7
---
SV-230275:
Old: 0
New: 0.5
---
SV-230329:
Old: 0
New: 0.7
---
SV-230333:
Old: 0
New: 0.5
---
SV-230337:
Old: 0
New: 0.5
---
SV-230339:
Old: 0
New: 0.5
---
SV-230343:
Old: 0
New: 0.5
---
SV-230345:
Old: 0
New: 0.5
---
SV-230347:
Old: 0
New: 0.5
---
SV-230351:
Old: 0
New: 0.5
---
SV-230352:
Old: 0
New: 0.5
---
SV-230354:
Old: 0
New: 0.5
---
SV-230502:
Old: 0
New: 0.5
---
SV-230530:
Old: 0
New: 0.7
---
SV-230550:
Old: 0
New: 0.5
---
SV-230557:
Old: 0
New: 0.5
---
SV-244519:
Old: 0
New: 0.5
---
SV-244521:
Old: 0
New: 0.5
---
SV-244530:
Old: 0
New: 0.5
---
SV-244534:
Old: 0
New: 0.5
---
SV-244535:
Old: 0
New: 0.5
---
SV-244536:
Old: 0
New: 0.5
---
SV-244538:
Old: 0
New: 0.5
---
SV-244539:
Old: 0
New: 0.5
---
</details>

### Updated Titles
<details>
  <summary>Click to expand.</summary>
SV-230222:
Old: RHEL 8 vendor packaged system security patches and updates must be
installed and up to date.
New: RHEL 8 vendor packaged system security patches and updates must be installed and up to date.
---
SV-230224:
Old: All RHEL 8 local disk partitions must implement cryptographic
mechanisms to prevent unauthorized disclosure or modification of all
information that requires at rest protection.
New: All RHEL 8 local disk partitions must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection.
---
SV-230225:
Old: RHEL 8 must display the Standard Mandatory DoD Notice and Consent
Banner before granting local or remote access to the system via a ssh logon.
New: RHEL 8 must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a ssh logon.
---
SV-230226:
Old: RHEL 8 must display the Standard Mandatory DoD Notice and Consent
Banner before granting local or remote access to the system via a graphical
user logon.
New: RHEL 8 must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.
---
SV-230227:
Old: RHEL 8 must display the Standard Mandatory DoD Notice and Consent
Banner before granting local or remote access to the system via a command line
user logon.
New: RHEL 8 must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a command line user logon.
---
SV-230229:
Old: RHEL 8, for PKI-based authentication, must validate certificates by
constructing a certification path (which includes status information) to an
accepted trust anchor.
New: RHEL 8, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.
---
SV-230230:
Old: RHEL 8, for certificate-based authentication, must enforce authorized
access to the corresponding private key.
New: RHEL 8, for certificate-based authentication, must enforce authorized access to the corresponding private key.
---
SV-230231:
Old: RHEL 8 must encrypt all stored passwords with a FIPS 140-2 approved
cryptographic hashing algorithm.
New: RHEL 8 must encrypt all stored passwords with a FIPS 140-2 approved cryptographic hashing algorithm.
---
SV-230232:
Old: RHEL 8 must employ FIPS 140-2 approved cryptographic hashing
algorithms for all stored passwords.
New: RHEL 8 must employ FIPS 140-2 approved cryptographic hashing algorithms for all stored passwords.
---
SV-230234:
Old: RHEL 8 operating systems booted with United Extensible Firmware
Interface (UEFI) must require authentication upon booting into single-user mode
and maintenance.
New: RHEL 8 operating systems booted with United Extensible Firmware Interface (UEFI) must require authentication upon booting into single-user mode and maintenance.
---
SV-230235:
Old: RHEL 8 operating systems booted with a BIOS must require
authentication upon booting into single-user and maintenance modes.
New: RHEL 8 operating systems booted with a BIOS must require authentication upon booting into single-user and maintenance modes.
---
SV-230236:
Old: RHEL 8 operating systems must require authentication upon booting into
rescue mode.
New: RHEL 8 operating systems must require authentication upon booting into rescue mode.
---
SV-230237:
Old: The RHEL 8 pam_unix.so module must be configured in the password-auth
file to use a FIPS 140-2 approved cryptographic hashing algorithm for system
authentication.
New: The RHEL 8 pam_unix.so module must be configured in the password-auth file to use a FIPS 140-2 approved cryptographic hashing algorithm for system authentication.
---
SV-230238:
Old: RHEL 8 must prevent system daemons from using Kerberos for
authentication.
New: RHEL 8 must prevent system daemons from using Kerberos for authentication.
---
SV-230240:
Old: RHEL 8 must use a Linux Security Module configured to enforce limits
on system services.
New: RHEL 8 must use a Linux Security Module configured to enforce limits on system services.
---
SV-230243:
Old: A sticky bit must be set on all RHEL 8 public directories to prevent
unauthorized and unintended information transferred via shared system
resources.
New: A sticky bit must be set on all RHEL 8 public directories to prevent unauthorized and unintended information transferred via shared system resources.
---
SV-230245:
Old: The RHEL 8 &#x2F;var&#x2F;log&#x2F;messages file must have mode 0640 or less
permissive.
New: The RHEL 8 &#x2F;var&#x2F;log&#x2F;messages file must have mode 0640 or less permissive.
---
SV-230251:
Old: The RHEL 8 SSH server must be configured to use only Message
Authentication Codes (MACs) employing FIPS 140-2 validated cryptographic hash
algorithms.
New: The RHEL 8 SSH server must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-2 validated cryptographic hash algorithms.
---
SV-230252:
Old: The RHEL 8 operating system must implement DoD-approved encryption to
protect the confidentiality of SSH server connections.
New: The RHEL 8 operating system must implement DoD-approved encryption to protect the confidentiality of SSH server connections.
---
SV-230254:
Old: The RHEL 8 operating system must implement DoD-approved encryption in
the OpenSSL package.
New: The RHEL 8 operating system must implement DoD-approved encryption in the OpenSSL package.
---
SV-230255:
Old: The RHEL 8 operating system must implement DoD-approved TLS encryption
in the OpenSSL package.
New: The RHEL 8 operating system must implement DoD-approved TLS encryption in the OpenSSL package.
---
SV-230256:
Old: The RHEL 8 operating system must implement DoD-approved TLS encryption
in the GnuTLS package.
New: The RHEL 8 operating system must implement DoD-approved TLS encryption in the GnuTLS package.
---
SV-230257:
Old: RHEL 8 system commands must have mode 0755 or less permissive.
New: RHEL 8 system commands must have mode 755 or less permissive.
---
SV-230259:
Old: RHEL 8 system commands must be group-owned by root or a system
account.
New: RHEL 8 system commands must be group-owned by root or a system account.
---
SV-230260:
Old: RHEL 8 library files must have mode 0755 or less permissive.
New: RHEL 8 library files must have mode 755 or less permissive.
---
SV-230263:
Old: The RHEL 8 file integrity tool must notify the system administrator
when changes to the baseline configuration or anomalies in the operation of any
security functions are discovered within an organizationally defined frequency.
New: The RHEL 8 file integrity tool must notify the system administrator when changes to the baseline configuration or anomalies in the operation of any security functions are discovered within an organizationally defined frequency.
---
SV-230264:
Old: RHEL 8 must prevent the installation of software, patches, service
packs, device drivers, or operating system components from a repository without
verification they have been digitally signed using a certificate that is issued
by a Certificate Authority (CA) that is recognized and approved by the
organization.
New: RHEL 8 must prevent the installation of software, patches, service packs, device drivers, or operating system components from a repository without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization.
---
SV-230265:
Old: RHEL 8 must prevent the installation of software, patches, service
packs, device drivers, or operating system components of local packages without
verification they have been digitally signed using a certificate that is issued
by a Certificate Authority (CA) that is recognized and approved by the
organization.
New: RHEL 8 must prevent the installation of software, patches, service packs, device drivers, or operating system components of local packages without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization.
---
SV-230267:
Old: RHEL 8 must enable kernel parameters to enforce discretionary access
control on symlinks.
New: RHEL 8 must enable kernel parameters to enforce discretionary access control on symlinks.
---
SV-230268:
Old: RHEL 8 must enable kernel parameters to enforce discretionary access
control on hardlinks.
New: RHEL 8 must enable kernel parameters to enforce discretionary access control on hardlinks.
---
SV-230271:
Old: RHEL 8 must require users to provide a password for privilege
escalation.
New: RHEL 8 must require users to provide a password for privilege escalation.
---
SV-230273:
Old: RHEL 8 must have the packages required for multifactor authentication
installed.
New: RHEL 8 must have the packages required for multifactor authentication installed.
---
SV-230274:
Old: RHEL 8 must implement certificate status checking for multifactor
authentication.
New: RHEL 8 must implement certificate status checking for multifactor authentication.
---
SV-230276:
Old: RHEL 8 must implement non-executable data to protect its memory from
unauthorized code execution.
New: RHEL 8 must implement non-executable data to protect its memory from unauthorized code execution.
---
SV-230277:
Old: RHEL 8 must clear the page allocator to prevent use-after-free
attacks.
New: RHEL 8 must clear the page allocator to prevent use-after-free attacks.
---
SV-230280:
Old: RHEL 8 must implement address space layout randomization (ASLR) to
protect its memory from unauthorized code execution.
New: RHEL 8 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution.
---
SV-230281:
Old: YUM must remove all software components after updated versions have
been installed on RHEL 8.
New: YUM must remove all software components after updated versions have been installed on RHEL 8.
---
SV-230285:
Old: RHEL 8 must enable the hardware random number generator entropy
gatherer service.
New: RHEL 8 must enable the hardware random number generator entropy gatherer service.
---
SV-230286:
Old: The RHEL 8 SSH public host key files must have mode 0644 or less
permissive.
New: The RHEL 8 SSH public host key files must have mode 0644 or less permissive.
---
SV-230288:
Old: The RHEL 8 SSH daemon must perform strict mode checking of home
directory configuration files.
New: The RHEL 8 SSH daemon must perform strict mode checking of home directory configuration files.
---
SV-230290:
Old: The RHEL 8 SSH daemon must not allow authentication using known host’s
authentication.
New: The RHEL 8 SSH daemon must not allow authentication using known host’s authentication.
---
SV-230291:
Old: The RHEL 8 SSH daemon must not allow Kerberos authentication, except
to fulfill documented and validated mission requirements.
New: The RHEL 8 SSH daemon must not allow Kerberos authentication, except to fulfill documented and validated mission requirements.
---
SV-230296:
Old: RHEL 8 must not permit direct logons to the root account using remote
access via SSH.
New: RHEL 8 must not permit direct logons to the root account using remote access via SSH.
---
SV-230299:
Old: RHEL 8 must prevent files with the setuid and setgid bit set from
being executed on file systems that contain user home directories.
New: RHEL 8 must prevent files with the setuid and setgid bit set from being executed on file systems that contain user home directories.
---
SV-230300:
Old: RHEL 8 must prevent files with the setuid and setgid bit set from
being executed on the &#x2F;boot directory.
New: RHEL 8 must prevent files with the setuid and setgid bit set from being executed on the &#x2F;boot directory.
---
SV-230302:
Old: RHEL 8 must prevent code from being executed on file systems that
contain user home directories.
New: RHEL 8 must prevent code from being executed on file systems that contain user home directories.
---
SV-230303:
Old: RHEL 8 must prevent special devices on file systems that are used with
removable media.
New: RHEL 8 must prevent special devices on file systems that are used with removable media.
---
SV-230304:
Old: RHEL 8 must prevent code from being executed on file systems that are
used with removable media.
New: RHEL 8 must prevent code from being executed on file systems that are used with removable media.
---
SV-230305:
Old: RHEL 8 must prevent files with the setuid and setgid bit set from
being executed on file systems that are used with removable media.
New: RHEL 8 must prevent files with the setuid and setgid bit set from being executed on file systems that are used with removable media.
---
SV-230306:
Old: RHEL 8 must prevent code from being executed on file systems that are
imported via Network File System (NFS).
New: RHEL 8 must prevent code from being executed on file systems that are imported via Network File System (NFS).
---
SV-230307:
Old: RHEL 8 must prevent special devices on file systems that are imported
via Network File System (NFS).
New: RHEL 8 must prevent special devices on file systems that are imported via Network File System (NFS).
---
SV-230308:
Old: RHEL 8 must prevent files with the setuid and setgid bit set from
being executed on file systems that are imported via Network File System (NFS).
New: RHEL 8 must prevent files with the setuid and setgid bit set from being executed on file systems that are imported via Network File System (NFS).
---
SV-230309:
Old: Local RHEL 8 initialization files must not execute world-writable
programs.
New: Local RHEL 8 initialization files must not execute world-writable programs.
---
SV-230316:
Old: For RHEL 8 systems using Domain Name Servers (DNS) resolution, at
least two name servers must be configured.
New: For RHEL 8 systems using Domain Name Servers (DNS) resolution, at least two name servers must be configured.
---
SV-230317:
Old: Executable search paths within the initialization files of all local
interactive RHEL 8 users must only contain paths that resolve to the system
default or the users home directory.
New: Executable search paths within the initialization files of all local interactive RHEL 8 users must only contain paths that resolve to the system default or the users home directory.
---
SV-230318:
Old: All RHEL 8 world-writable directories must be owned by root, sys, bin,
or an application user.
New: All RHEL 8 world-writable directories must be owned by root, sys, bin, or an application user.
---
SV-230319:
Old: All RHEL 8 world-writable directories must be group-owned by root,
sys, bin, or an application group.
New: All RHEL 8 world-writable directories must be group-owned by root, sys, bin, or an application group.
---
SV-230320:
Old: All RHEL 8 local interactive users must have a home directory assigned
in the &#x2F;etc&#x2F;passwd file.
New: All RHEL 8 local interactive users must have a home directory assigned in the &#x2F;etc&#x2F;passwd file.
---
SV-230321:
Old: All RHEL 8 local interactive user home directories must have mode 0750
or less permissive.
New: All RHEL 8 local interactive user home directories must have mode 0750 or less permissive.
---
SV-230322:
Old: All RHEL 8 local interactive user home directories must be group-owned
by the home directory owner’s primary group.
New: All RHEL 8 local interactive user home directories must be group-owned by the home directory owner’s primary group.
---
SV-230323:
Old: All RHEL 8 local interactive user home directories defined in the
&#x2F;etc&#x2F;passwd file must exist.
New: All RHEL 8 local interactive user home directories defined in the &#x2F;etc&#x2F;passwd file must exist.
---
SV-230324:
Old: All RHEL 8 local interactive user accounts must be assigned a home
directory upon creation.
New: All RHEL 8 local interactive user accounts must be assigned a home directory upon creation.
---
SV-230325:
Old: All RHEL 8 local initialization files must have mode 0740 or less
permissive.
New: All RHEL 8 local initialization files must have mode 0740 or less permissive.
---
SV-230328:
Old: A separate RHEL 8 filesystem must be used for user home directories
(such as &#x2F;home or an equivalent).
New: A separate RHEL 8 filesystem must be used for user home directories (such as &#x2F;home or an equivalent).
---
SV-230329:
Old: Unattended or automatic logon via the RHEL 8 graphical user interface
must not be allowed.
New: Unattended or automatic logon via the RHEL 8 graphical user interface must not be allowed.
---
SV-230331:
Old: RHEL 8 temporary user accounts must be provisioned with an expiration
time of 72 hours or less.
New: RHEL 8 temporary user accounts must be provisioned with an expiration time of 72 hours or less.
---
SV-230332:
Old: RHEL 8 must automatically lock an account when three unsuccessful
logon attempts occur.
New: RHEL 8 must automatically lock an account when three unsuccessful logon attempts occur.
---
SV-230333:
Old: RHEL 8 must automatically lock an account when three unsuccessful
logon attempts occur.
New: RHEL 8 must automatically lock an account when three unsuccessful logon attempts occur.
---
SV-230334:
Old: RHEL 8 must automatically lock an account when three unsuccessful
logon attempts occur during a 15-minute time period.
New: RHEL 8 must automatically lock an account when three unsuccessful logon attempts occur during a 15-minute time period.
---
SV-230335:
Old: RHEL 8 must automatically lock an account when three unsuccessful
logon attempts occur during a 15-minute time period.
New: RHEL 8 must automatically lock an account when three unsuccessful logon attempts occur during a 15-minute time period.
---
SV-230336:
Old: RHEL 8 must automatically lock an account until the locked account is
released by an administrator when three unsuccessful logon attempts occur
during a 15-minute time period.
New: RHEL 8 must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period.
---
SV-230337:
Old: RHEL 8 must automatically lock an account until the locked account is
released by an administrator when three unsuccessful logon attempts occur
during a 15-minute time period.
New: RHEL 8 must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period.
---
SV-230340:
Old: RHEL 8 must prevent system messages from being presented when three
unsuccessful logon attempts occur.
New: RHEL 8 must prevent system messages from being presented when three unsuccessful logon attempts occur.
---
SV-230341:
Old: RHEL 8 must prevent system messages from being presented when three
unsuccessful logon attempts occur.
New: RHEL 8 must prevent system messages from being presented when three unsuccessful logon attempts occur.
---
SV-230342:
Old: RHEL 8 must log user name information when unsuccessful logon attempts
occur.
New: RHEL 8 must log user name information when unsuccessful logon attempts occur.
---
SV-230343:
Old: RHEL 8 must log user name information when unsuccessful logon attempts
occur.
New: RHEL 8 must log user name information when unsuccessful logon attempts occur.
---
SV-230344:
Old: RHEL 8 must include root when automatically locking an account until
the locked account is released by an administrator when three unsuccessful
logon attempts occur during a 15-minute time period.
New: RHEL 8 must include root when automatically locking an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period.
---
SV-230345:
Old: RHEL 8 must include root when automatically locking an account until
the locked account is released by an administrator when three unsuccessful
logon attempts occur during a 15-minute time period.
New: RHEL 8 must include root when automatically locking an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period.
---
SV-230346:
Old: RHEL 8 must limit the number of concurrent sessions to ten for all
accounts and&#x2F;or account types.
New: RHEL 8 must limit the number of concurrent sessions to ten for all accounts and&#x2F;or account types.
---
SV-230347:
Old: RHEL 8 must enable a user session lock until that user re-establishes
access using established identification and authentication procedures for
graphical user sessions.
New: RHEL 8 must enable a user session lock until that user re-establishes access using established identification and authentication procedures for graphical user sessions.
---
SV-230348:
Old: RHEL 8 must enable a user session lock until that user re-establishes
access using established identification and authentication procedures for
command line sessions.
New: RHEL 8 must enable a user session lock until that user re-establishes access using established identification and authentication procedures for command line sessions.
---
SV-230349:
Old: RHEL 8 must ensure session control is automatically started at shell
initialization.
New: RHEL 8 must ensure session control is automatically started at shell initialization.
---
SV-230351:
Old: RHEL 8 must be able to initiate directly a session lock for all
connection types using smartcard when the smartcard is removed.
New: RHEL 8 must be able to initiate directly a session lock for all connection types using smartcard when the smartcard is removed.
---
SV-230352:
Old: RHEL 8 must automatically lock graphical user sessions after 15
minutes of inactivity.
New: RHEL 8 must automatically lock graphical user sessions after 15 minutes of inactivity.
---
SV-230353:
Old: RHEL 8 must automatically lock command line user sessions after 15
minutes of inactivity.
New: RHEL 8 must automatically lock command line user sessions after 15 minutes of inactivity.
---
SV-230354:
Old: RHEL 8 must prevent a user from overriding the session lock-delay
setting for the graphical user interface.
New: RHEL 8 must prevent a user from overriding the session lock-delay setting for the graphical user interface.
---
SV-230355:
Old: RHEL 8 must map the authenticated identity to the user or group
account for PKI-based authentication.
New: RHEL 8 must map the authenticated identity to the user or group account for PKI-based authentication.
---
SV-230357:
Old: RHEL 8 must enforce password complexity by requiring that at least one
uppercase character be used.
New: RHEL 8 must enforce password complexity by requiring that at least one uppercase character be used.
---
SV-230358:
Old: RHEL 8 must enforce password complexity by requiring that at least one
lower-case character be used.
New: RHEL 8 must enforce password complexity by requiring that at least one lower-case character be used.
---
SV-230359:
Old: RHEL 8 must enforce password complexity by requiring that at least one
numeric character be used.
New: RHEL 8 must enforce password complexity by requiring that at least one numeric character be used.
---
SV-230360:
Old: RHEL 8 must require the maximum number of repeating characters of the
same character class be limited to four when passwords are changed.
New: RHEL 8 must require the maximum number of repeating characters of the same character class be limited to four when passwords are changed.
---
SV-230361:
Old: RHEL 8 must require the maximum number of repeating characters be
limited to three when passwords are changed.
New: RHEL 8 must require the maximum number of repeating characters be limited to three when passwords are changed.
---
SV-230362:
Old: RHEL 8 must require the change of at least four character classes when
passwords are changed.
New: RHEL 8 must require the change of at least four character classes when passwords are changed.
---
SV-230363:
Old: RHEL 8 must require the change of at least 8 characters when passwords
are changed.
New: RHEL 8 must require the change of at least 8 characters when passwords are changed.
---
SV-230364:
Old: RHEL 8 passwords must have a 24 hours&#x2F;1 day minimum password lifetime
restriction in &#x2F;etc&#x2F;shadow.
New: RHEL 8 passwords must have a 24 hours&#x2F;1 day minimum password lifetime restriction in &#x2F;etc&#x2F;shadow.
---
SV-230365:
Old: RHEL 8 passwords for new users or password changes must have a 24
hours&#x2F;1 day minimum password lifetime restriction in &#x2F;etc&#x2F;logins.def.
New: RHEL 8 passwords for new users or password changes must have a 24 hours&#x2F;1 day minimum password lifetime restriction in &#x2F;etc&#x2F;login.defs.
---
SV-230366:
Old: RHEL 8 user account passwords must have a 60-day maximum password
lifetime restriction.
New: RHEL 8 user account passwords must have a 60-day maximum password lifetime restriction.
---
SV-230367:
Old: RHEL 8 user account passwords must be configured so that existing
passwords are restricted to a 60-day maximum lifetime.
New: RHEL 8 user account passwords must be configured so that existing passwords are restricted to a 60-day maximum lifetime.
---
SV-230368:
Old: RHEL 8 passwords must be prohibited from reuse for a minimum of five
generations.
New: RHEL 8 must be configured in the password-auth file to prohibit password reuse for a minimum of five generations.
---
SV-230372:
Old: RHEL 8 must implement smart card logon for multifactor authentication
for access to interactive accounts.
New: RHEL 8 must implement smart card logon for multifactor authentication for access to interactive accounts.
---
SV-230373:
Old: RHEL 8 account identifiers (individuals, groups, roles, and devices)
must be disabled after 35 days of inactivity.
New: RHEL 8 account identifiers (individuals, groups, roles, and devices) must be disabled after 35 days of inactivity.
---
SV-230374:
Old: RHEL 8 emergency accounts must be automatically removed or disabled
after the crisis is resolved or within 72 hours.
New: RHEL 8 must automatically expire temporary accounts within 72 hours.
---
SV-230378:
Old: RHEL 8 must enforce a delay of at least four seconds between logon
prompts following a failed logon attempt.
New: RHEL 8 must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.
---
SV-230380:
Old: RHEL 8 must not allow accounts configured with blank or null
passwords.
New: RHEL 8 must not allow accounts configured with blank or null passwords.
---
SV-230381:
Old: RHEL 8 must display the date and time of the last successful account
logon upon logon.
New: RHEL 8 must display the date and time of the last successful account logon upon logon.
---
SV-230382:
Old: RHEL 8 must display the date and time of the last successful account
logon upon an SSH logon.
New: RHEL 8 must display the date and time of the last successful account logon upon an SSH logon.
---
SV-230383:
Old: RHEL 8 must define default permissions for all authenticated users in
such a way that the user can only read and modify their own files.
New: RHEL 8 must define default permissions for all authenticated users in such a way that the user can only read and modify their own files.
---
SV-230384:
Old: RHEL 8 must set the umask value to 077 for all local interactive user
accounts.
New: RHEL 8 must set the umask value to 077 for all local interactive user accounts.
---
SV-230386:
Old: The RHEL 8 audit system must be configured to audit the execution of
privileged functions and prevent all software from executing at higher
privilege levels than users executing the software.
New: The RHEL 8 audit system must be configured to audit the execution of privileged functions and prevent all software from executing at higher privilege levels than users executing the software.
---
SV-230388:
Old: The RHEL 8 System Administrator (SA) and Information System Security
Officer (ISSO) (at a minimum) must be alerted of an audit processing failure
event.
New: The RHEL 8 System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) must be alerted of an audit processing failure event.
---
SV-230389:
Old: The RHEL 8 Information System Security Officer (ISSO) and System
Administrator (SA) (at a minimum) must have mail aliases to be notified of an
audit processing failure.
New: The RHEL 8 Information System Security Officer (ISSO) and System Administrator (SA) (at a minimum) must have mail aliases to be notified of an audit processing failure.
---
SV-230390:
Old: The RHEL 8 System must take appropriate action when an audit
processing failure occurs.
New: The RHEL 8 System must take appropriate action when an audit processing failure occurs.
---
SV-230392:
Old: The RHEL 8 audit system must take appropriate action when the audit
storage volume is full.
New: The RHEL 8 audit system must take appropriate action when the audit storage volume is full.
---
SV-230394:
Old: RHEL 8 must label all off-loaded audit logs before sending them to the
central log server.
New: RHEL 8 must label all off-loaded audit logs before sending them to the central log server.
---
SV-230396:
Old: RHEL 8 audit logs must have a mode of 0600 or less permissive to
prevent unauthorized read access.
New: RHEL 8 audit logs must have a mode of 0600 or less permissive to prevent unauthorized read access.
---
SV-230397:
Old: RHEL 8 audit logs must be owned by root to prevent unauthorized read
access.
New: RHEL 8 audit logs must be owned by root to prevent unauthorized read access.
---
SV-230398:
Old: RHEL 8 audit logs must be group-owned by root to prevent unauthorized
read access.
New: RHEL 8 audit logs must be group-owned by root to prevent unauthorized read access.
---
SV-230399:
Old: RHEL 8 audit log directory must be owned by root to prevent
unauthorized read access.
New: RHEL 8 audit log directory must be owned by root to prevent unauthorized read access.
---
SV-230400:
Old: RHEL 8 audit log directory must be group-owned by root to prevent
unauthorized read access.
New: RHEL 8 audit log directory must be group-owned by root to prevent unauthorized read access.
---
SV-230401:
Old: RHEL 8 audit log directory must have a mode of 0700 or less permissive
to prevent unauthorized read access.
New: RHEL 8 audit log directory must have a mode of 0700 or less permissive to prevent unauthorized read access.
---
SV-230402:
Old: RHEL 8 audit system must protect auditing rules from unauthorized
change.
New: RHEL 8 audit system must protect auditing rules from unauthorized change.
---
SV-230404:
Old: RHEL 8 must generate audit records for all account creations,
modifications, disabling, and termination events that affect &#x2F;etc&#x2F;shadow.
New: RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect &#x2F;etc&#x2F;shadow.
---
SV-230405:
Old: RHEL 8 must generate audit records for all account creations,
modifications, disabling, and termination events that affect
&#x2F;etc&#x2F;security&#x2F;opasswd.
New: RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect &#x2F;etc&#x2F;security&#x2F;opasswd.
---
SV-230406:
Old: RHEL 8 must generate audit records for all account creations,
modifications, disabling, and termination events that affect &#x2F;etc&#x2F;passwd.
New: RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect &#x2F;etc&#x2F;passwd.
---
SV-230407:
Old: RHEL 8 must generate audit records for all account creations,
modifications, disabling, and termination events that affect &#x2F;etc&#x2F;gshadow.
New: RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect &#x2F;etc&#x2F;gshadow.
---
SV-230408:
Old: RHEL 8 must generate audit records for all account creations,
modifications, disabling, and termination events that affect &#x2F;etc&#x2F;group.
New: RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect &#x2F;etc&#x2F;group.
---
SV-230409:
Old: RHEL 8 must generate audit records for all account creations,
modifications, disabling, and termination events that affect &#x2F;etc&#x2F;sudoers.
New: RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect &#x2F;etc&#x2F;sudoers.
---
SV-230410:
Old: RHEL 8 must generate audit records for all account creations,
modifications, disabling, and termination events that affect &#x2F;etc&#x2F;sudoers.d&#x2F;.
New: RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect &#x2F;etc&#x2F;sudoers.d&#x2F;.
---
SV-230412:
Old: Successful&#x2F;unsuccessful uses of the su command in RHEL 8 must generate
an audit record.
New: Successful&#x2F;unsuccessful uses of the su command in RHEL 8 must generate an audit record.
---
SV-230413:
Old: The RHEL 8 audit system must be configured to audit any usage of the
lremovexattr system call.
New: The RHEL 8 audit system must be configured to audit any usage of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls.
---
SV-230418:
Old: Successful&#x2F;unsuccessful uses of the chage command in RHEL 8 must
generate an audit record.
New: Successful&#x2F;unsuccessful uses of the chage command in RHEL 8 must generate an audit record.
---
SV-230419:
Old: Successful&#x2F;unsuccessful uses of the chcon command in RHEL 8 must
generate an audit record.
New: Successful&#x2F;unsuccessful uses of the chcon command in RHEL 8 must generate an audit record.
---
SV-230421:
Old: Successful&#x2F;unsuccessful uses of the ssh-agent in RHEL 8 must generate
an audit record.
New: Successful&#x2F;unsuccessful uses of the ssh-agent in RHEL 8 must generate an audit record.
---
SV-230422:
Old: Successful&#x2F;unsuccessful uses of the passwd command in RHEL 8 must
generate an audit record.
New: Successful&#x2F;unsuccessful uses of the passwd command in RHEL 8 must generate an audit record.
---
SV-230423:
Old: Successful&#x2F;unsuccessful uses of the mount command in RHEL 8 must
generate an audit record.
New: Successful&#x2F;unsuccessful uses of the mount command in RHEL 8 must generate an audit record.
---
SV-230424:
Old: Successful&#x2F;unsuccessful uses of the umount command in RHEL 8 must
generate an audit record.
New: Successful&#x2F;unsuccessful uses of the umount command in RHEL 8 must generate an audit record.
---
SV-230425:
Old: Successful&#x2F;unsuccessful uses of the mount syscall in RHEL 8 must
generate an audit record.
New: Successful&#x2F;unsuccessful uses of the mount syscall in RHEL 8 must generate an audit record.
---
SV-230426:
Old: Successful&#x2F;unsuccessful uses of the unix_update in RHEL 8 must
generate an audit record.
New: Successful&#x2F;unsuccessful uses of the unix_update in RHEL 8 must generate an audit record.
---
SV-230427:
Old: Successful&#x2F;unsuccessful uses of postdrop in RHEL 8 must generate an
audit record.
New: Successful&#x2F;unsuccessful uses of postdrop in RHEL 8 must generate an audit record.
---
SV-230428:
Old: Successful&#x2F;unsuccessful uses of postqueue in RHEL 8 must generate an
audit record.
New: Successful&#x2F;unsuccessful uses of postqueue in RHEL 8 must generate an audit record.
---
SV-230429:
Old: Successful&#x2F;unsuccessful uses of semanage in RHEL 8 must generate an
audit record.
New: Successful&#x2F;unsuccessful uses of semanage in RHEL 8 must generate an audit record.
---
SV-230430:
Old: Successful&#x2F;unsuccessful uses of setfiles in RHEL 8 must generate an
audit record.
New: Successful&#x2F;unsuccessful uses of setfiles in RHEL 8 must generate an audit record.
---
SV-230431:
Old: Successful&#x2F;unsuccessful uses of userhelper in RHEL 8 must generate an
audit record.
New: Successful&#x2F;unsuccessful uses of userhelper in RHEL 8 must generate an audit record.
---
SV-230432:
Old: Successful&#x2F;unsuccessful uses of setsebool in RHEL 8 must generate an
audit record.
New: Successful&#x2F;unsuccessful uses of setsebool in RHEL 8 must generate an audit record.
---
SV-230433:
Old: Successful&#x2F;unsuccessful uses of unix_chkpwd in RHEL 8 must generate an
audit record.
New: Successful&#x2F;unsuccessful uses of unix_chkpwd in RHEL 8 must generate an audit record.
---
SV-230434:
Old: Successful&#x2F;unsuccessful uses of the ssh-keysign in RHEL 8 must
generate an audit record.
New: Successful&#x2F;unsuccessful uses of the ssh-keysign in RHEL 8 must generate an audit record.
---
SV-230435:
Old: Successful&#x2F;unsuccessful uses of the setfacl command in RHEL 8 must
generate an audit record.
New: Successful&#x2F;unsuccessful uses of the setfacl command in RHEL 8 must generate an audit record.
---
SV-230436:
Old: Successful&#x2F;unsuccessful uses of the pam_timestamp_check command in
RHEL 8 must generate an audit record.
New: Successful&#x2F;unsuccessful uses of the pam_timestamp_check command in RHEL 8 must generate an audit record.
---
SV-230437:
Old: Successful&#x2F;unsuccessful uses of the newgrp command in RHEL 8 must
generate an audit record.
New: Successful&#x2F;unsuccessful uses of the newgrp command in RHEL 8 must generate an audit record.
---
SV-230438:
Old: Successful&#x2F;unsuccessful uses of the init_module command in RHEL 8 must
generate an audit record.
New: Successful&#x2F;unsuccessful uses of the init_module and finit_module system calls in RHEL 8 must generate an audit record.
---
SV-230439:
Old: Successful&#x2F;unsuccessful uses of the rename command in RHEL 8 must
generate an audit record.
New: Successful&#x2F;unsuccessful uses of the rename, unlink, rmdir, renameat, and unlinkat system calls in RHEL 8 must generate an audit record.
---
SV-230444:
Old: Successful&#x2F;unsuccessful uses of the gpasswd command in RHEL 8 must
generate an audit record.
New: Successful&#x2F;unsuccessful uses of the gpasswd command in RHEL 8 must generate an audit record.
---
SV-230446:
Old: Successful&#x2F;unsuccessful uses of the delete_module command in RHEL 8
must generate an audit record.
New: Successful&#x2F;unsuccessful uses of the delete_module command in RHEL 8 must generate an audit record.
---
SV-230447:
Old: Successful&#x2F;unsuccessful uses of the crontab command in RHEL 8 must
generate an audit record.
New: Successful&#x2F;unsuccessful uses of the crontab command in RHEL 8 must generate an audit record.
---
SV-230448:
Old: Successful&#x2F;unsuccessful uses of the chsh command in RHEL 8 must
generate an audit record.
New: Successful&#x2F;unsuccessful uses of the chsh command in RHEL 8 must generate an audit record.
---
SV-230449:
Old: Successful&#x2F;unsuccessful uses of the truncate command in RHEL 8 must
generate an audit record.
New: Successful&#x2F;unsuccessful uses of the truncate, ftruncate, creat, open, openat, and open_by_handle_at system calls in RHEL 8 must generate an audit record.
---
SV-230455:
Old: Successful&#x2F;unsuccessful uses of the chown command in RHEL 8 must
generate an audit record.
New: Successful&#x2F;unsuccessful uses of the chown, fchown, fchownat, and lchown system calls in RHEL 8 must generate an audit record.
---
SV-230456:
Old: Successful&#x2F;unsuccessful uses of the chmod command in RHEL 8 must
generate an audit record.
New: Successful&#x2F;unsuccessful uses of the chmod, fchmod, and fchmodat system calls in RHEL 8 must generate an audit record.
---
SV-230462:
Old: Successful&#x2F;unsuccessful uses of the sudo command in RHEL 8 must
generate an audit record.
New: Successful&#x2F;unsuccessful uses of the sudo command in RHEL 8 must generate an audit record.
---
SV-230463:
Old: Successful&#x2F;unsuccessful uses of the usermod command in RHEL 8 must
generate an audit record.
New: Successful&#x2F;unsuccessful uses of the usermod command in RHEL 8 must generate an audit record.
---
SV-230464:
Old: Successful&#x2F;unsuccessful uses of the chacl command in RHEL 8 must
generate an audit record.
New: Successful&#x2F;unsuccessful uses of the chacl command in RHEL 8 must generate an audit record.
---
SV-230465:
Old: Successful&#x2F;unsuccessful uses of the kmod command in RHEL 8 must
generate an audit record.
New: Successful&#x2F;unsuccessful uses of the kmod command in RHEL 8 must generate an audit record.
---
SV-230466:
Old: Successful&#x2F;unsuccessful modifications to the faillock log file in RHEL
8 must generate an audit record.
New: Successful&#x2F;unsuccessful modifications to the faillock log file in RHEL 8 must generate an audit record.
---
SV-230467:
Old: Successful&#x2F;unsuccessful modifications to the lastlog file in RHEL 8
must generate an audit record.
New: Successful&#x2F;unsuccessful modifications to the lastlog file in RHEL 8 must generate an audit record.
---
SV-230468:
Old: RHEL 8 must enable auditing of processes that start prior to the audit
daemon.
New: RHEL 8 must enable auditing of processes that start prior to the audit daemon.
---
SV-230469:
Old: RHEL 8 must allocate an audit_backlog_limit of sufficient size to
capture processes that start prior to the audit daemon.
New: RHEL 8 must allocate an audit_backlog_limit of sufficient size to capture processes that start prior to the audit daemon.
---
SV-230471:
Old: RHEL 8 must allow only the Information System Security Manager (ISSM)
(or individuals or roles appointed by the ISSM) to select which auditable
events are to be audited.
New: RHEL 8 must allow only the Information System Security Manager (ISSM) (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.
---
SV-230475:
Old: RHEL 8 must use cryptographic mechanisms to protect the integrity of
audit tools.
New: RHEL 8 must use cryptographic mechanisms to protect the integrity of audit tools.
---
SV-230476:
Old: RHEL 8 must allocate audit record storage capacity to store at least
one week of audit records, when audit records are not immediately sent to a
central audit record storage facility.
New: RHEL 8 must allocate audit record storage capacity to store at least one week of audit records, when audit records are not immediately sent to a central audit record storage facility.
---
SV-230477:
Old: RHEL 8 must have the packages required for offloading audit logs
installed.
New: RHEL 8 must have the packages required for offloading audit logs installed.
---
SV-230478:
Old: RHEL 8 must have the packages required for encrypting offloaded audit
logs installed.
New: RHEL 8 must have the packages required for encrypting offloaded audit logs installed.
---
SV-230479:
Old: The RHEL 8 audit records must be off-loaded onto a different system or
storage media from the system being audited.
New: The RHEL 8 audit records must be off-loaded onto a different system or storage media from the system being audited.
---
SV-230480:
Old: RHEL 8 must take appropriate action when the internal event queue is
full.
New: RHEL 8 must take appropriate action when the internal event queue is full.
---
SV-230481:
Old: RHEL 8 must encrypt the transfer of audit records off-loaded onto a
different system or media from the system being audited.
New: RHEL 8 must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited.
---
SV-230482:
Old: RHEL 8 must authenticate the remote logging server for off-loading
audit logs.
New: RHEL 8 must authenticate the remote logging server for off-loading audit logs.
---
SV-230483:
Old: RHEL 8 must take action when allocated audit record storage volume
reaches 75 percent of the repository maximum audit record storage capacity.
New: RHEL 8 must take action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.
---
SV-230484:
Old: RHEL 8 must securely compare internal information system clocks at
least every 24 hours with a server synchronized to an authoritative time
source, such as the United States Naval Observatory (USNO) time servers, or a
time server designated for the appropriate DoD network (NIPRNet&#x2F;SIPRNet),
and&#x2F;or the Global Positioning System (GPS).
New: RHEL 8 must securely compare internal information system clocks at least every 24 hours with a server synchronized to an authoritative time source, such as the United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DoD network (NIPRNet&#x2F;SIPRNet), and&#x2F;or the Global Positioning System (GPS).
---
SV-230491:
Old: RHEL 8 must enable mitigations against processor-based
vulnerabilities.
New: RHEL 8 must enable mitigations against processor-based vulnerabilities.
---
SV-230493:
Old: RHEL 8 must cover or disable the built-in or attached camera when not
in use.
New: RHEL 8 must cover or disable the built-in or attached camera when not in use.
---
SV-230497:
Old: RHEL 8 must disable the transparent inter-process communication (TIPC)
protocol.
New: RHEL 8 must disable the transparent inter-process communication (TIPC) protocol.
---
SV-230500:
Old: RHEL 8 must be configured to prohibit or restrict the use of
functions, ports, protocols, and&#x2F;or services, as defined in the Ports,
Protocols, and Services Management (PPSM) Category Assignments List (CAL) and
vulnerability assessments.
New: RHEL 8 must be configured to prohibit or restrict the use of functions, ports, protocols, and&#x2F;or services, as defined in the Ports, Protocols, and Services Management (PPSM) Category Assignments List (CAL) and vulnerability assessments.
---
SV-230504:
Old: A RHEL 8 firewall must employ a deny-all, allow-by-exception policy
for allowing connections to other systems.
New: A RHEL 8 firewall must employ a deny-all, allow-by-exception policy for allowing connections to other systems.
---
SV-230524:
Old: RHEL 8 must block unauthorized peripherals before establishing a
connection.
New: RHEL 8 must block unauthorized peripherals before establishing a connection.
---
SV-230525:
Old: A firewall must be able to protect against or limit the effects of
Denial of Service (DoS) attacks by ensuring RHEL 8 can implement rate-limiting
measures on impacted network interfaces.
New: A firewall must be able to protect against or limit the effects of Denial of Service (DoS) attacks by ensuring RHEL 8 can implement rate-limiting measures on impacted network interfaces.
---
SV-230526:
Old: All RHEL 8 networked systems must have and implement SSH to protect
the confidentiality and integrity of transmitted and received information, as
well as information during preparation for transmission.
New: All RHEL 8 networked systems must have and implement SSH to protect the confidentiality and integrity of transmitted and received information, as well as information during preparation for transmission.
---
SV-230527:
Old: RHEL 8 must force a frequent session key renegotiation for SSH
connections to the server.
New: RHEL 8 must force a frequent session key renegotiation for SSH connections to the server.
---
SV-230530:
Old: The x86 Ctrl-Alt-Delete key sequence in RHEL 8 must be disabled if a
graphical user interface is installed.
New: The x86 Ctrl-Alt-Delete key sequence in RHEL 8 must be disabled if a graphical user interface is installed.
---
SV-230531:
Old: The systemd Ctrl-Alt-Delete burst key sequence in RHEL 8 must be
disabled.
New: The systemd Ctrl-Alt-Delete burst key sequence in RHEL 8 must be disabled.
---
SV-230533:
Old: The Trivial File Transfer Protocol (TFTP) server package must not be
installed if not required for RHEL 8 operational support.
New: The Trivial File Transfer Protocol (TFTP) server package must not be installed if not required for RHEL 8 operational support.
---
SV-230534:
Old: The root account must be the only account having unrestricted access
to the RHEL 8 system.
New: The root account must be the only account having unrestricted access to the RHEL 8 system.
---
SV-230535:
Old: RHEL 8 must prevent IPv6 Internet Control Message Protocol (ICMP)
redirect messages from being accepted.
New: RHEL 8 must prevent IPv6 Internet Control Message Protocol (ICMP) redirect messages from being accepted.
---
SV-230536:
Old: RHEL 8 must not send Internet Control Message Protocol (ICMP)
redirects.
New: RHEL 8 must not send Internet Control Message Protocol (ICMP) redirects.
---
SV-230537:
Old: RHEL 8 must not respond to Internet Control Message Protocol (ICMP)
echoes sent to a broadcast address.
New: RHEL 8 must not respond to Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.
---
SV-230540:
Old: RHEL 8 must not be performing packet forwarding unless the system is a
router.
New: RHEL 8 must not enable IPv6 packet forwarding unless the system is a router.
---
SV-230542:
Old: RHEL 8 must not accept router advertisements on all IPv6 interfaces by
default.
New: RHEL 8 must not accept router advertisements on all IPv6 interfaces by default.
---
SV-230543:
Old: RHEL 8 must not allow interfaces to perform Internet Control Message
Protocol (ICMP) redirects by default.
New: RHEL 8 must not allow interfaces to perform Internet Control Message Protocol (ICMP) redirects by default.
---
SV-230544:
Old: RHEL 8 must ignore IPv6 Internet Control Message Protocol (ICMP)
redirect messages.
New: RHEL 8 must ignore IPv6 Internet Control Message Protocol (ICMP) redirect messages.
---
SV-230545:
Old: RHEL 8 must disable access to network bpf syscall from unprivileged
processes.
New: RHEL 8 must disable access to network bpf syscall from unprivileged processes.
---
SV-230551:
Old: The RHEL 8 file integrity tool must be configured to verify extended
attributes.
New: The RHEL 8 file integrity tool must be configured to verify extended attributes.
---
SV-230552:
Old: The RHEL 8 file integrity tool must be configured to verify Access
Control Lists (ACLs).
New: The RHEL 8 file integrity tool must be configured to verify Access Control Lists (ACLs).
---
SV-230553:
Old: The graphical display manager must not be installed on RHEL 8 unless
approved.
New: The graphical display manager must not be installed on RHEL 8 unless approved.
---
SV-230555:
Old: RHEL 8 remote X connections for interactive users must be disabled
unless to fulfill documented and validated mission requirements.
New: RHEL 8 remote X connections for interactive users must be disabled unless to fulfill documented and validated mission requirements.
---
SV-230556:
Old: The RHEL 8 SSH daemon must prevent remote hosts from connecting to the
proxy display.
New: The RHEL 8 SSH daemon must prevent remote hosts from connecting to the proxy display.
---
SV-230557:
Old: If the Trivial File Transfer Protocol (TFTP) server is required, the
RHEL 8 TFTP daemon must be configured to operate in secure mode.
New: If the Trivial File Transfer Protocol (TFTP) server is required, the RHEL 8 TFTP daemon must be configured to operate in secure mode.
---
SV-230558:
Old: A File Transfer Protocol (FTP) server package must not be installed
unless mission essential on RHEL 8.
New: A File Transfer Protocol (FTP) server package must not be installed unless mission essential on RHEL 8.
---
SV-230559:
Old: The gssproxy package must not be installed unless mission essential on
RHEL 8.
New: The gssproxy package must not be installed unless mission essential on RHEL 8.
---
SV-230560:
Old: The iprutils package must not be installed unless mission essential on
RHEL 8.
New: The iprutils package must not be installed unless mission essential on RHEL 8.
---
SV-230561:
Old: The tuned package must not be installed unless mission essential on
RHEL 8.
New: The tuned package must not be installed unless mission essential on RHEL 8.
---
SV-237642:
Old: RHEL 8 must use the invoking user&#39;s password for privilege escalation
when using &quot;sudo&quot;.
New: RHEL 8 must use the invoking user&#39;s password for privilege escalation when using &quot;sudo&quot;.
---
SV-244519:
Old: RHEL 8 must display a banner before granting local or remote access to
the system via a graphical user logon.
New: RHEL 8 must display a banner before granting local or remote access to the system via a graphical user logon.
---
SV-244521:
Old: RHEL 8 operating systems booted with United Extensible Firmware
Interface (UEFI) must require a unique superusers name upon booting into
single-user mode and maintenance.
New: RHEL 8 operating systems booted with United Extensible Firmware Interface (UEFI) must require a unique superusers name upon booting into single-user mode and maintenance.
---
SV-244522:
Old: RHEL 8 operating systems booted with a BIOS must require  a unique
superusers name upon booting into single-user and maintenance modes.
New: RHEL 8 operating systems booted with a BIOS must require  a unique superusers name upon booting into single-user and maintenance modes.
---
SV-244523:
Old: RHEL 8 operating systems must require authentication upon booting into
emergency mode.
New: RHEL 8 operating systems must require authentication upon booting into emergency mode.
---
SV-244524:
Old: The RHEL 8 pam_unix.so module must be configured in the system-auth
file to use a FIPS 140-2 approved cryptographic hashing algorithm for system
authentication.
New: The RHEL 8 pam_unix.so module must be configured in the system-auth file to use a FIPS 140-2 approved cryptographic hashing algorithm for system authentication.
---
SV-244525:
Old: The RHEL 8 SSH daemon must be configured with a timeout interval.
New: RHEL 8 must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive.
---
SV-244526:
Old: The RHEL 8 SSH daemon must be configured to use system-wide crypto
policies.
New: The RHEL 8 SSH daemon must be configured to use system-wide crypto policies.
---
SV-244527:
Old: RHEL 8 must have the packages required to use the hardware random
number generator entropy gatherer service.
New: RHEL 8 must have the packages required to use the hardware random number generator entropy gatherer service.
---
SV-244528:
Old: The RHEL 8 SSH daemon must not allow GSSAPI authentication, except to
fulfill documented and validated mission requirements.
New: The RHEL 8 SSH daemon must not allow GSSAPI authentication, except to fulfill documented and validated mission requirements.
---
SV-244530:
Old: RHEL 8 must prevent files with the setuid and setgid bit set from
being executed on the &#x2F;boot&#x2F;efi directory.
New: RHEL 8 must prevent files with the setuid and setgid bit set from being executed on the &#x2F;boot&#x2F;efi directory.
---
SV-244531:
Old: All RHEL 8 local interactive user home directory files must have mode
0750 or less permissive.
New: All RHEL 8 local interactive user home directory files must have mode 0750 or less permissive.
---
SV-244532:
Old: RHEL 8 must be configured so that all files and directories contained
in local interactive user home directories are group-owned by a group of which
the home directory owner is a member.
New: RHEL 8 must be configured so that all files and directories contained in local interactive user home directories are group-owned by a group of which the home directory owner is a member.
---
SV-244533:
Old: RHEL 8 must configure the use of the pam_faillock.so module in the
&#x2F;etc&#x2F;pam.d&#x2F;system-auth file.
New: RHEL 8 must configure the use of the pam_faillock.so module in the &#x2F;etc&#x2F;pam.d&#x2F;system-auth file.
---
SV-244534:
Old: RHEL 8 must configure the use of the pam_faillock.so module in the
&#x2F;etc&#x2F;pam.d&#x2F;password-auth file.
New: RHEL 8 must configure the use of the pam_faillock.so module in the &#x2F;etc&#x2F;pam.d&#x2F;password-auth file.
---
SV-244535:
Old: RHEL 8 must initiate a session lock for graphical user interfaces when
the screensaver is activated.
New: RHEL 8 must initiate a session lock for graphical user interfaces when the screensaver is activated.
---
SV-244536:
Old: RHEL 8 must disable the user list at logon for graphical user
interfaces.
New: RHEL 8 must disable the user list at logon for graphical user interfaces.
---
SV-244538:
Old: RHEL 8 must prevent a user from overriding the session idle-delay
setting for the graphical user interface.
New: RHEL 8 must prevent a user from overriding the session idle-delay setting for the graphical user interface.
---
SV-244539:
Old: RHEL 8 must prevent a user from overriding the screensaver
lock-enabled setting for the graphical user interface.
New: RHEL 8 must prevent a user from overriding the screensaver lock-enabled setting for the graphical user interface.
---
SV-244541:
Old: RHEL 8 must not allow blank or null passwords in the password-auth
file.
New: RHEL 8 must not allow blank or null passwords in the password-auth file.
---
SV-244542:
Old: RHEL 8 audit records must contain information to establish what type
of events occurred, the source of events, where events occurred, and the
outcome of events.
New: RHEL 8 audit records must contain information to establish what type of events occurred, the source of events, where events occurred, and the outcome of events.
---
SV-244543:
Old: RHEL 8 must notify the System Administrator (SA) and Information
System Security Officer (ISSO) (at a minimum) when allocated audit record
storage volume 75 percent utilization.
New: RHEL 8 must notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when allocated audit record storage volume 75 percent utilization.
---
SV-244546:
Old: The RHEL 8 fapolicy module must be configured to employ a deny-all,
permit-by-exception policy to allow the execution of authorized software
programs.
New: The RHEL 8 fapolicy module must be configured to employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.
---
SV-244550:
Old: RHEL 8 must prevent IPv4 Internet Control Message Protocol (ICMP)
redirect messages from being accepted.
New: RHEL 8 must prevent IPv4 Internet Control Message Protocol (ICMP) redirect messages from being accepted.
---
SV-244553:
Old: RHEL 8 must ignore IPv4 Internet Control Message Protocol (ICMP)
redirect messages.
New: RHEL 8 must ignore IPv4 Internet Control Message Protocol (ICMP) redirect messages.
---
SV-244554:
Old: RHEL 8 must enable hardening for the Berkeley Packet Filter
Just-in-time compiler.
New: RHEL 8 must enable hardening for the Berkeley Packet Filter Just-in-time compiler.
---
SV-245540:
Old: The RHEL 8 operating system must implement the Endpoint Security for
Linux Threat Prevention tool.
New: The RHEL 8 operating system must implement the Endpoint Security for Linux Threat Prevention tool.
---
</details>

### Updated Descriptions
<details>
  <summary>Click to expand.</summary>
SV-230221:
Old:
```
An operating system release is considered "supported" if the vendor
continues to provide security patches for the product. With an unsupported
release, it will not be possible to resolve security issues discovered in the
system software.

    Red Hat offers the Extended Update Support (EUS) ad-on to a Red Hat
Enterprise Linux subscription, for a fee, for those customers who wish to
standardize on a specific minor release for an extended period. The RHEL 8
minor releases eligible for EUS are 8.1, 8.2, 8.4, 8.6, and 8.8. Each RHEL 8
EUS stream is available for 24 months from the availability of the minor
release. RHEL 8.10 will be the final minor release overall. For more details on
the Red Hat Enterprise Linux Life Cycle  visit
https://access.redhat.com/support/policy/updates/errata.

```
New:
```
An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.

Red Hat offers the Extended Update Support (EUS) add-on to a Red Hat Enterprise Linux subscription, for a fee, for those customers who wish to standardize on a specific minor release for an extended period. The RHEL 8 minor releases eligible for EUS are 8.1, 8.2, 8.4, 8.6, and 8.8. Each RHEL 8 EUS stream is available for 24 months from the availability of the minor release. RHEL 8.10 will be the final minor release overall. For more details on the Red Hat Enterprise Linux Life Cycle  visit https://access.redhat.com/support/policy/updates/errata/.
Note: The life-cycle time spans and dates are subject to adjustment.

```
---
SV-230222:
Old:
```
Timely patching is critical for maintaining the operational
availability, confidentiality, and integrity of information technology (IT)
systems. However, failure to keep operating system and application software
patched is a common mistake made by IT professionals. New patches are released
daily, and it is often difficult for even experienced System Administrators to
keep abreast of all the new patches. When new weaknesses in an operating system
exist, patches are usually made available by the vendor to resolve the
problems. If the most recent security patches and updates are not installed,
unauthorized users may take advantage of weaknesses in the unpatched software.
The lack of prompt attention to patching could result in a system compromise.

```
New:
```
Timely patching is critical for maintaining the operational availability, confidentiality, and integrity of information technology (IT) systems. However, failure to keep operating system and application software patched is a common mistake made by IT professionals. New patches are released daily, and it is often difficult for even experienced System Administrators to keep abreast of all the new patches. When new weaknesses in an operating system exist, patches are usually made available by the vendor to resolve the problems. If the most recent security patches and updates are not installed, unauthorized users may take advantage of weaknesses in the unpatched software. The lack of prompt attention to patching could result in a system compromise.

```
---
SV-230223:
Old:
```
Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

RHEL 8 utilizes GRUB 2 as the default bootloader. Note that GRUB 2 command-line parameters are defined in the "kernelopts" variable of the /boot/grub2/grubenv file for all kernel boot entries. The command "fips-mode-setup" modifies the "kernelopts" variable, which in turn updates all kernel boot entries.

The fips=1 kernel option needs to be added to the kernel command line during system installation so that key generation is done with FIPS-approved algorithms and continuous monitoring tests in place. Users must also ensure the system has plenty of entropy during the installation process by moving the mouse around, or if no mouse is available, ensuring that many keystrokes are typed. The recommended amount of keystrokes is 256 and more. Less than 256 keystrokes may generate a nonunique key.

```
New:
```
Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

RHEL 8 utilizes GRUB 2 as the default bootloader. Note that GRUB 2 command-line parameters are defined in the "kernelopts" variable of the /boot/grub2/grubenv file for all kernel boot entries. The command "fips-mode-setup" modifies the "kernelopts" variable, which in turn updates all kernel boot entries. 

The fips=1 kernel option needs to be added to the kernel command line during system installation so that key generation is done with FIPS-approved algorithms and continuous monitoring tests in place. Users must also ensure the system has plenty of entropy during the installation process by moving the mouse around, or if no mouse is available, ensuring that many keystrokes are typed. The recommended amount of keystrokes is 256 and more. Less than 256 keystrokes may generate a nonunique key.



```
---
SV-230224:
Old:
```
RHEL 8 systems handling data requiring "data at rest" protections
must employ cryptographic mechanisms to prevent unauthorized disclosure and
modification of the information at rest.

    Selection of a cryptographic mechanism is based on the need to protect the
integrity of organizational information. The strength of the mechanism is
commensurate with the security category and/or classification of the
information. Organizations have the flexibility to either encrypt all
information on storage devices (i.e., full disk encryption) or encrypt specific
data structures (e.g., files, records, or fields).

```
New:
```
RHEL 8 systems handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).



```
---
SV-230225:
Old:
```
Display of a standardized and approved use notification before
granting access to the operating system ensures privacy and security
notification verbiage used is consistent with applicable federal laws,
Executive Orders, directives, policies, regulations, standards, and guidance.

    System use notifications are required only for access via logon interfaces
with human users and are not required when such human interfaces do not exist.

    The banner must be formatted in accordance with applicable DoD policy. Use
the following verbiage for operating systems that can accommodate banners of
1300 characters:

    "You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only.

    By using this IS (which includes any device attached to this IS), you
consent to the following conditions:

    -The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are
subject to routine monitoring, interception, and search, and may be disclosed
or used for any USG-authorized purpose.

    -This IS includes security measures (e.g., authentication and access
controls) to protect USG interests--not for your personal benefit or privacy.

    -Notwithstanding the above, using this IS does not constitute consent to
PM, LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services
by attorneys, psychotherapists, or clergy, and their assistants. Such
communications and work product are private and confidential. See User
Agreement for details."

    Use the following verbiage for operating systems that have severe
limitations on the number of characters that can be displayed in the banner:

    "I've read and consent to terms in IS user agreem't."

```
New:
```
Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:

"I've read & consent to terms in IS user agreem't."



```
---
SV-230226:
Old:
```
Display of a standardized and approved use notification before
granting access to the operating system ensures privacy and security
notification verbiage used is consistent with applicable federal laws,
Executive Orders, directives, policies, regulations, standards, and guidance.

    System use notifications are required only for access via logon interfaces
with human users and are not required when such human interfaces do not exist.

    The banner must be formatted in accordance with applicable DoD policy. Use
the following verbiage for operating systems that can accommodate banners of
1300 characters:

    "You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only.

    By using this IS (which includes any device attached to this IS), you
consent to the following conditions:

    -The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are
subject to routine monitoring, interception, and search, and may be disclosed
or used for any USG-authorized purpose.

    -This IS includes security measures (e.g., authentication and access
controls) to protect USG interests--not for your personal benefit or privacy.

    -Notwithstanding the above, using this IS does not constitute consent to
PM, LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services
by attorneys, psychotherapists, or clergy, and their assistants. Such
communications and work product are private and confidential. See User
Agreement for details."

```
New:
```
Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."



```
---
SV-230227:
Old:
```
Display of a standardized and approved use notification before
granting access to the operating system ensures privacy and security
notification verbiage used is consistent with applicable federal laws,
Executive Orders, directives, policies, regulations, standards, and guidance.

    System use notifications are required only for access via logon interfaces
with human users and are not required when such human interfaces do not exist.

    The banner must be formatted in accordance with applicable DoD policy. Use
the following verbiage for operating systems that can accommodate banners of
1300 characters:

    "You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only.

    By using this IS (which includes any device attached to this IS), you
consent to the following conditions:

    -The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are
subject to routine monitoring, interception, and search, and may be disclosed
or used for any USG-authorized purpose.

    -This IS includes security measures (e.g., authentication and access
controls) to protect USG interests--not for your personal benefit or privacy.

    -Notwithstanding the above, using this IS does not constitute consent to
PM, LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services
by attorneys, psychotherapists, or clergy, and their assistants. Such
communications and work product are private and confidential. See User
Agreement for details."

```
New:
```
Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."



```
---
SV-230228:
Old:
```
Remote access services, such as those providing remote access to
network devices and information systems, which lack automated monitoring
capabilities, increase risk and make remote user access management difficult at
best.

    Remote access is access to DoD nonpublic information systems by an
authorized user (or an information system) communicating through an external,
non-organization-controlled network. Remote access methods include, for
example, dial-up, broadband, and wireless.

    Automated monitoring of remote access sessions allows organizations to
detect cyber attacks and ensure ongoing compliance with remote access policies
by auditing connection activities of remote access capabilities, such as Remote
Desktop Protocol (RDP), on a variety of information system components (e.g.,
servers, workstations, notebook computers, smartphones, and tablets).

```
New:
```
Remote access services, such as those providing remote access to network devices and information systems, which lack automated monitoring capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Automated monitoring of remote access sessions allows organizations to detect cyber attacks and ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).

```
---
SV-230229:
Old:
```
Without path validation, an informed trust decision by the relying
party cannot be made when presented with any certificate not already explicitly
trusted.

    A trust anchor is an authoritative entity represented via a public key and
associated data. It is used in the context of public key infrastructures, X.509
digital certificates, and DNSSEC.

    When there is a chain of trust, usually the top entity to be trusted
becomes the trust anchor; it can be, for example, a Certification Authority
(CA). A certification path starts with the subject certificate and proceeds
through a number of intermediate certificates up to a trusted root certificate,
typically issued by a trusted CA.

    This requirement verifies that a certification path to an accepted trust
anchor is used for certificate validation and that the path includes status
information. Path validation is necessary for a relying party to make an
informed trust decision when presented with any certificate not already
explicitly trusted. Status information for certification paths includes
certificate revocation lists or online certificate status protocol responses.
Validation of the certificate status information is out of scope for this
requirement.

```
New:
```
Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.

A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC.

When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA.

This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.



```
---
SV-230230:
Old:
```
If an unauthorized user obtains access to a private key without a
passcode, that user would have unauthorized access to any system where the
associated public key has been installed.

```
New:
```
If an unauthorized user obtains access to a private key without a passcode, that user would have unauthorized access to any system where the associated public key has been installed.

```
---
SV-230231:
Old:
```
Passwords need to be protected at all times, and encryption is the
standard method for protecting passwords. If passwords are not encrypted, they
can be plainly read (i.e., clear text) and easily compromised.

    Unapproved mechanisms that are used for authentication to the cryptographic
module are not verified and therefore cannot be relied upon to provide
confidentiality or integrity, and DoD data may be compromised.

    FIPS 140-2 is the current standard for validating that mechanisms used to
access cryptographic modules utilize authentication that meets DoD requirements.

```
New:
```
Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements.

```
---
SV-230232:
Old:
```
The system must use a strong hashing algorithm to store the password.

    Passwords need to be protected at all times, and encryption is the standard
method for protecting passwords. If passwords are not encrypted, they can be
plainly read (i.e., clear text) and easily compromised.

```
New:
```
The system must use a strong hashing algorithm to store the password.

Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

```
---
SV-230233:
Old:
```
The system must use a strong hashing algorithm to store the password.
The system must use a sufficient number of hashing rounds to ensure the
required level of entropy.

    Passwords need to be protected at all times, and encryption is the standard
method for protecting passwords. If passwords are not encrypted, they can be
plainly read (i.e., clear text) and easily compromised.

```
New:
```
The system must use a strong hashing algorithm to store the password. The system must use a sufficient number of hashing rounds to ensure the required level of entropy.

Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

```
---
SV-230234:
Old:
```
If the system does not require valid authentication before it boots
into single-user or maintenance mode, anyone who invokes single-user or
maintenance mode is granted privileged access to all files on the system. GRUB
2 is the default boot loader for RHEL 8 and is designed to require a password
to boot into single-user mode or make modifications to the boot menu.

```
New:
```
If the system does not require valid authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 8 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.

```
---
SV-230235:
Old:
```
If the system does not require valid authentication before it boots
into single-user or maintenance mode, anyone who invokes single-user or
maintenance mode is granted privileged access to all files on the system. GRUB
2 is the default boot loader for RHEL 8 and is designed to require a password
to boot into single-user mode or make modifications to the boot menu.

```
New:
```
If the system does not require valid authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 8 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.

```
---
SV-230236:
Old:
```
If the system does not require valid root authentication before it
boots into emergency or rescue mode, anyone who invokes emergency or rescue
mode is granted privileged access to all files on the system.

```
New:
```
If the system does not require valid root authentication before it boots into emergency or rescue mode, anyone who invokes emergency or rescue mode is granted privileged access to all files on the system.

```
---
SV-230237:
Old:
```
Unapproved mechanisms that are used for authentication to the
cryptographic module are not verified and therefore cannot be relied upon to
provide confidentiality or integrity, and DoD data may be compromised.

    RHEL 8 systems utilizing encryption are required to use FIPS-compliant
mechanisms for authenticating to cryptographic modules.

    FIPS 140-2 is the current standard for validating that mechanisms used to
access cryptographic modules utilize authentication that meets DoD
requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a
general-purpose computing system.

```
New:
```
Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

RHEL 8 systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules. 

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general-purpose computing system.

```
---
SV-230238:
Old:
```
Unapproved mechanisms that are used for authentication to the
cryptographic module are not verified and therefore cannot be relied upon to
provide confidentiality or integrity, and DoD data may be compromised.

    RHEL 8 systems utilizing encryption are required to use FIPS-compliant
mechanisms for authenticating to cryptographic modules.

    The key derivation function (KDF) in Kerberos is not FIPS compatible.
Ensuring the system does not have any keytab files present prevents system
daemons from using Kerberos for authentication.  A keytab is a file containing
pairs of Kerberos principals and encrypted keys.

    FIPS 140-2 is the current standard for validating that mechanisms used to
access cryptographic modules utilize authentication that meets DoD
requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a
general-purpose computing system.

```
New:
```
Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

RHEL 8 systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

The key derivation function (KDF) in Kerberos is not FIPS compatible.  Ensuring the system does not have any keytab files present prevents system daemons from using Kerberos for authentication.  A keytab is a file containing pairs of Kerberos principals and encrypted keys.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general-purpose computing system.

```
---
SV-230239:
Old:
```
Unapproved mechanisms that are used for authentication to the
cryptographic module are not verified and therefore cannot be relied upon to
provide confidentiality or integrity, and DoD data may be compromised.

    RHEL 8 systems utilizing encryption are required to use FIPS-compliant
mechanisms for authenticating to cryptographic modules.

    Currently, Kerberos does not utilize FIPS 140-2 cryptography.

    FIPS 140-2 is the current standard for validating that mechanisms used to
access cryptographic modules utilize authentication that meets DoD
requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a
general-purpose computing system.

```
New:
```
Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

RHEL 8 systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

Currently, Kerberos does not utilize FIPS 140-2 cryptography.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general-purpose computing system.

```
---
SV-230240:
Old:
```
Without verification of the security functions, security functions may
not operate correctly and the failure may go unnoticed. Security function is
defined as the hardware, software, and/or firmware of the information system
responsible for enforcing the system security policy and supporting the
isolation of code and data on which the protection is based. Security
functionality includes, but is not limited to, establishing system accounts,
configuring access authorizations (i.e., permissions, privileges), setting
events to be audited, and setting intrusion detection parameters.

    This requirement applies to operating systems performing security function
verification/testing and/or systems and environments that require this
functionality.

```
New:
```
Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.

```
---
SV-230241:
Old:
```
Without verification of the security functions, security functions may
not operate correctly and the failure may go unnoticed. Security function is
defined as the hardware, software, and/or firmware of the information system
responsible for enforcing the system security policy and supporting the
isolation of code and data on which the protection is based. Security
functionality includes, but is not limited to, establishing system accounts,
configuring access authorizations (i.e., permissions, privileges), setting
events to be audited, and setting intrusion detection parameters.

    Policycoreutils contains the policy core utilities that are required for
basic operation of an SELinux-enabled system. These utilities include
load_policy to load SELinux policies, setfile to label filesystems, newrole to
switch roles, and run_init to run /etc/init.d scripts in the proper context.

```
New:
```
Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Policycoreutils contains the policy core utilities that are required for basic operation of an SELinux-enabled system. These utilities include load_policy to load SELinux policies, setfile to label filesystems, newrole to switch roles, and run_init to run /etc/init.d scripts in the proper context.

```
---
SV-230243:
Old:
```
Preventing unauthorized information transfers mitigates the risk of
information, including encrypted representations of information, produced by
the actions of prior users/roles (or the actions of processes acting on behalf
of prior users/roles) from being available to any current users/roles (or
current processes) that obtain access to shared system resources (e.g.,
registers, main memory, hard disks) after those resources have been released
back to information systems. The control of information in shared resources is
also commonly referred to as object reuse and residual information protection.

    This requirement generally applies to the design of an information
technology product, but it can also apply to the configuration of particular
information system components that are, or use, such products. This can be
verified by acceptance/validation processes in DoD or other government agencies.

    There may be shared resources with configurable protections (e.g., files in
storage) that may be assessed on specific information system components.

```
New:
```
Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of particular information system components that are, or use, such products. This can be verified by acceptance/validation processes in DoD or other government agencies.

There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information system components.

```
---
SV-230244:
Old:
```
Terminating an unresponsive SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, deallocating associated TCP/IP address/port pairs at the operating system level and deallocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean the operating system terminates all sessions or network access; it only ends the unresponsive session and releases the resources associated with that session.

RHEL 8 uses /etc/ssh/sshd_config for configurations of OpenSSH. Within the sshd_config, the product of the values of "ClientAliveInterval" and "ClientAliveCountMax" is used to establish the inactivity threshold. The "ClientAliveInterval" is a timeout interval in seconds after which if no data has been received from the client, sshd will send a message through the encrypted channel to request a response from the client. The "ClientAliveCountMax" is the number of client alive messages that may be sent without sshd receiving any messages back from the client. If this threshold is met, sshd will disconnect the client. For more information on these settings and others, refer to the sshd_config man pages.

```
New:
```
Terminating an unresponsive SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, deallocating associated TCP/IP address/port pairs at the operating system level and deallocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean the operating system terminates all sessions or network access; it only ends the unresponsive session and releases the resources associated with that session.

RHEL 8 uses /etc/ssh/sshd_config for configurations of OpenSSH. Within the sshd_config, the product of the values of "ClientAliveInterval" and "ClientAliveCountMax" is used to establish the inactivity threshold. The "ClientAliveInterval" is a timeout interval in seconds after which if no data has been received from the client, sshd will send a message through the encrypted channel to request a response from the client. The "ClientAliveCountMax" is the number of client alive messages that may be sent without sshd receiving any messages back from the client. If this threshold is met, sshd will disconnect the client. For more information on these settings and others, refer to the sshd_config man pages.



```
---
SV-230245:
Old:
```
Only authorized personnel should be aware of errors and the details of
the errors. Error messages are an indicator of an organization's operational
state or can identify the RHEL 8 system or platform. Additionally, Personally
Identifiable Information (PII) and operational information must not be revealed
through error messages to unauthorized personnel or their designated
representatives.

    The structure and content of error messages must be carefully considered by
the organization and development team. The extent to which the information
system is able to identify and handle error conditions is guided by
organizational policy and operational requirements.

```
New:
```
Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the RHEL 8 system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.

```
---
SV-230246:
Old:
```
Only authorized personnel should be aware of errors and the details of
the errors. Error messages are an indicator of an organization's operational
state or can identify the RHEL 8 system or platform. Additionally, Personally
Identifiable Information (PII) and operational information must not be revealed
through error messages to unauthorized personnel or their designated
representatives.

    The structure and content of error messages must be carefully considered by
the organization and development team. The extent to which the information
system is able to identify and handle error conditions is guided by
organizational policy and operational requirements.

```
New:
```
Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the RHEL 8 system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.

```
---
SV-230247:
Old:
```
Only authorized personnel should be aware of errors and the details of
the errors. Error messages are an indicator of an organization's operational
state or can identify the RHEL 8 system or platform. Additionally, Personally
Identifiable Information (PII) and operational information must not be revealed
through error messages to unauthorized personnel or their designated
representatives.

    The structure and content of error messages must be carefully considered by
the organization and development team. The extent to which the information
system is able to identify and handle error conditions is guided by
organizational policy and operational requirements.

```
New:
```
Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the RHEL 8 system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.

```
---
SV-230248:
Old:
```
Only authorized personnel should be aware of errors and the details of
the errors. Error messages are an indicator of an organization's operational
state or can identify the RHEL 8 system or platform. Additionally, Personally
Identifiable Information (PII) and operational information must not be revealed
through error messages to unauthorized personnel or their designated
representatives.

    The structure and content of error messages must be carefully considered by
the organization and development team. The extent to which the information
system is able to identify and handle error conditions is guided by
organizational policy and operational requirements.

```
New:
```
Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the RHEL 8 system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.

```
---
SV-230249:
Old:
```
Only authorized personnel should be aware of errors and the details of
the errors. Error messages are an indicator of an organization's operational
state or can identify the RHEL 8 system or platform. Additionally, Personally
Identifiable Information (PII) and operational information must not be revealed
through error messages to unauthorized personnel or their designated
representatives.

    The structure and content of error messages must be carefully considered by
the organization and development team. The extent to which the information
system is able to identify and handle error conditions is guided by
organizational policy and operational requirements.

```
New:
```
Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the RHEL 8 system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.

```
---
SV-230250:
Old:
```
Only authorized personnel should be aware of errors and the details of
the errors. Error messages are an indicator of an organization's operational
state or can identify the RHEL 8 system or platform. Additionally, Personally
Identifiable Information (PII) and operational information must not be revealed
through error messages to unauthorized personnel or their designated
representatives.

    The structure and content of error messages must be carefully considered by
the organization and development team. The extent to which the information
system is able to identify and handle error conditions is guided by
organizational policy and operational requirements.

```
New:
```
Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the RHEL 8 system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.

```
---
SV-230251:
Old:
```
Without cryptographic integrity protections, information can be
altered by unauthorized users without detection.

    Remote access (e.g., RDP) is access to DoD nonpublic information systems by
an authorized user (or an information system) communicating through an
external, non-organization-controlled network. Remote access methods include,
for example, dial-up, broadband, and wireless.

    Cryptographic mechanisms used for protecting the integrity of information
include, for example, signed hash functions using asymmetric cryptography
enabling distribution of the public key to verify the hash information while
maintaining the confidentiality of the secret key used to generate the hash.

    RHEL 8 incorporates system-wide crypto policies by default. The SSH
configuration file has no effect on the ciphers, MACs, or algorithms unless
specifically defined in the /etc/sysconfig/sshd file. The employed algorithms
can be viewed in the /etc/crypto-policies/back-ends/opensshserver.config file.

    The system will attempt to use the first hash presented by the client that
matches the server list. Listing the values "strongest to weakest" is a
method to ensure the use of the strongest hash available to secure the SSH
connection.

```
New:
```
Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

RHEL 8 incorporates system-wide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the /etc/sysconfig/sshd file. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/opensshserver.config file.

The system will attempt to use the first hash presented by the client that matches the server list. Listing the values "strongest to weakest" is a method to ensure the use of the strongest hash available to secure the SSH connection.



```
---
SV-230252:
Old:
```
Without cryptographic integrity protections, information can be
altered by unauthorized users without detection.

    Remote access (e.g., RDP) is access to DoD nonpublic information systems by
an authorized user (or an information system) communicating through an
external, non-organization-controlled network. Remote access methods include,
for example, dial-up, broadband, and wireless.

    Cryptographic mechanisms used for protecting the integrity of information
include, for example, signed hash functions using asymmetric cryptography
enabling distribution of the public key to verify the hash information while
maintaining the confidentiality of the secret key used to generate the hash.

    RHEL 8 incorporates system-wide crypto policies by default. The SSH
configuration file has no effect on the ciphers, MACs, or algorithms unless
specifically defined in the /etc/sysconfig/sshd file. The employed algorithms
can be viewed in the /etc/crypto-policies/back-ends/opensshserver.config file.

    The system will attempt to use the first hash presented by the client that
matches the server list. Listing the values "strongest to weakest" is a
method to ensure the use of the strongest hash available to secure the SSH
connection.

```
New:
```
Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

RHEL 8 incorporates system-wide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the /etc/sysconfig/sshd file. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/opensshserver.config file.

The system will attempt to use the first hash presented by the client that matches the server list. Listing the values "strongest to weakest" is a method to ensure the use of the strongest hash available to secure the SSH connection.



```
---
SV-230253:
Old:
```
The most important characteristic of a random number generator is its
randomness, namely its ability to deliver random numbers that are impossible to
predict.  Entropy in computer security is associated with the unpredictability
of a source of randomness.  The random source with high entropy tends to
achieve a uniform distribution of random values.  Random number generators are
one of the most important building blocks of cryptosystems.

    The SSH implementation in RHEL8 uses the OPENSSL library, which does not
use high-entropy sources by default.  By using the SSH_USE_STRONG_RNG
environment variable the OPENSSL random generator is reseeded from /dev/random.
 This setting is not recommended on computers without the hardware random
generator because insufficient entropy causes the connection to be blocked
until enough entropy is available.

```
New:
```
The most important characteristic of a random number generator is its randomness, namely its ability to deliver random numbers that are impossible to predict.  Entropy in computer security is associated with the unpredictability of a source of randomness.  The random source with high entropy tends to achieve a uniform distribution of random values.  Random number generators are one of the most important building blocks of cryptosystems.

The SSH implementation in RHEL8 uses the OPENSSL library, which does not use high-entropy sources by default.  By using the SSH_USE_STRONG_RNG environment variable the OPENSSL random generator is reseeded from /dev/random.  This setting is not recommended on computers without the hardware random generator because insufficient entropy causes the connection to be blocked until enough entropy is available.

```
---
SV-230254:
Old:
```
Without cryptographic integrity protections, information can be
altered by unauthorized users without detection.

    Remote access (e.g., RDP) is access to DoD nonpublic information systems by
an authorized user (or an information system) communicating through an
external, non-organization-controlled network. Remote access methods include,
for example, dial-up, broadband, and wireless.

    Cryptographic mechanisms used for protecting the integrity of information
include, for example, signed hash functions using asymmetric cryptography
enabling distribution of the public key to verify the hash information while
maintaining the confidentiality of the secret key used to generate the hash.

    RHEL 8 incorporates system-wide crypto policies by default.  The employed
algorithms can be viewed in the /etc/crypto-policies/back-ends/openssl.config
file.

```
New:
```
Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

RHEL 8 incorporates system-wide crypto policies by default.  The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/openssl.config file.



```
---
SV-230255:
Old:
```
Without cryptographic integrity protections, information can be
altered by unauthorized users without detection.

    Remote access (e.g., RDP) is access to DoD nonpublic information systems by
an authorized user (or an information system) communicating through an
external, non-organization-controlled network. Remote access methods include,
for example, dial-up, broadband, and wireless.

    Cryptographic mechanisms used for protecting the integrity of information
include, for example, signed hash functions using asymmetric cryptography
enabling distribution of the public key to verify the hash information while
maintaining the confidentiality of the secret key used to generate the hash.

    RHEL 8 incorporates system-wide crypto policies by default.  The employed
algorithms can be viewed in the /etc/crypto-policies/back-ends/openssl.config
file.

```
New:
```
Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

RHEL 8 incorporates system-wide crypto policies by default.  The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/openssl.config file.



```
---
SV-230256:
Old:
```
Without cryptographic integrity protections, information can be
altered by unauthorized users without detection.

    Transport Layer Security (TLS) encryption is a required security setting as
a number of known vulnerabilities have been reported against Secure Sockets
Layer (SSL) and earlier versions of TLS. Encryption of private information is
essential to ensuring data confidentiality. If private information is not
encrypted, it can be intercepted and easily read by an unauthorized party. SQL
Server must use a minimum of FIPS 140-2-approved TLS version 1.2, and all
non-FIPS-approved SSL and TLS versions must be disabled. NIST SP 800-52
specifies the preferred configurations for government systems.

    Cryptographic mechanisms used for protecting the integrity of information
include, for example, signed hash functions using asymmetric cryptography
enabling distribution of the public key to verify the hash information while
maintaining the confidentiality of the secret key used to generate the hash.

    The GnuTLS library offers an API to access secure communications protocols.
 SSLv2 is not available in the GnuTLS library.  The RHEL 8 system-wide crypto
policy defines employed algorithms in the
/etc/crypto-policies/back-ends/gnutls.config file.

```
New:
```
Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Transport Layer Security (TLS) encryption is a required security setting as a number of known vulnerabilities have been reported against Secure Sockets Layer (SSL) and earlier versions of TLS. Encryption of private information is essential to ensuring data confidentiality. If private information is not encrypted, it can be intercepted and easily read by an unauthorized party. SQL Server must use a minimum of FIPS 140-2-approved TLS version 1.2, and all non-FIPS-approved SSL and TLS versions must be disabled. NIST SP 800-52 specifies the preferred configurations for government systems.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

The GnuTLS library offers an API to access secure communications protocols.  SSLv2 is not available in the GnuTLS library.  The RHEL 8 system-wide crypto policy defines employed algorithms in the /etc/crypto-policies/back-ends/gnutls.config file.



```
---
SV-230257:
Old:
```
If RHEL 8 were to allow any user to make changes to software
libraries, then those changes might be implemented without undergoing the
appropriate testing and approvals that are part of a robust change management
process.

    This requirement applies to RHEL 8 with software libraries that are
accessible and configurable, as in the case of interpreted languages. Software
libraries also include privileged programs that execute with escalated
privileges. Only qualified and authorized individuals will be allowed to obtain
access to information system components for purposes of initiating changes,
including upgrades and modifications.

```
New:
```
If RHEL 8 were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to RHEL 8 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals will be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

```
---
SV-230258:
Old:
```
If RHEL 8 were to allow any user to make changes to software
libraries, then those changes might be implemented without undergoing the
appropriate testing and approvals that are part of a robust change management
process.

    This requirement applies to RHEL 8 with software libraries that are
accessible and configurable, as in the case of interpreted languages. Software
libraries also include privileged programs that execute with escalated
privileges. Only qualified and authorized individuals will be allowed to obtain
access to information system components for purposes of initiating changes,
including upgrades and modifications.

```
New:
```
If RHEL 8 were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to RHEL 8 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals will be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

```
---
SV-230259:
Old:
```
If RHEL 8 were to allow any user to make changes to software
libraries, then those changes might be implemented without undergoing the
appropriate testing and approvals that are part of a robust change management
process.

    This requirement applies to RHEL 8 with software libraries that are
accessible and configurable, as in the case of interpreted languages. Software
libraries also include privileged programs that execute with escalated
privileges. Only qualified and authorized individuals will be allowed to obtain
access to information system components for purposes of initiating changes,
including upgrades and modifications.

```
New:
```
If RHEL 8 were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to RHEL 8 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals will be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

```
---
SV-230260:
Old:
```
If RHEL 8 were to allow any user to make changes to software
libraries, then those changes might be implemented without undergoing the
appropriate testing and approvals that are part of a robust change management
process.

    This requirement applies to RHEL 8 with software libraries that are
accessible and configurable, as in the case of interpreted languages. Software
libraries also include privileged programs that execute with escalated
privileges. Only qualified and authorized individuals will be allowed to obtain
access to information system components for purposes of initiating changes,
including upgrades and modifications.

```
New:
```
If RHEL 8 were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to RHEL 8 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals will be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

```
---
SV-230261:
Old:
```
If RHEL 8 were to allow any user to make changes to software
libraries, then those changes might be implemented without undergoing the
appropriate testing and approvals that are part of a robust change management
process.

    This requirement applies to RHEL 8 with software libraries that are
accessible and configurable, as in the case of interpreted languages. Software
libraries also include privileged programs that execute with escalated
privileges. Only qualified and authorized individuals will be allowed to obtain
access to information system components for purposes of initiating changes,
including upgrades and modifications.

```
New:
```
If RHEL 8 were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to RHEL 8 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals will be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

```
---
SV-230262:
Old:
```
If RHEL 8 were to allow any user to make changes to software
libraries, then those changes might be implemented without undergoing the
appropriate testing and approvals that are part of a robust change management
process.

    This requirement applies to RHEL 8 with software libraries that are
accessible and configurable, as in the case of interpreted languages. Software
libraries also include privileged programs that execute with escalated
privileges. Only qualified and authorized individuals will be allowed to obtain
access to information system components for purposes of initiating changes,
including upgrades and modifications.

```
New:
```
If RHEL 8 were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to RHEL 8 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals will be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

```
---
SV-230263:
Old:
```
Unauthorized changes to the baseline configuration could make the
system vulnerable to various attacks or allow unauthorized access to the
operating system. Changes to operating system configurations can have
unintended side effects, some of which may be relevant to security.

    Detecting such changes and providing an automated response can help avoid
unintended, negative consequences that could ultimately affect the security
state of the operating system. The operating system's Information Management
Officer (IMO)/Information System Security Officer (ISSO) and System
Administrators (SAs) must be notified via email and/or monitoring system trap
when there is an unauthorized modification of a configuration item.

    Notifications provided by information systems include messages to local
computer consoles, and/or hardware indications, such as lights.

    This capability must take into account operational requirements for
availability for selecting an appropriate response. The organization may choose
to shut down or restart the information system upon security function anomaly
detection.

    RHEL 8 comes with many optional software packages. A file integrity tool
called Advanced Intrusion Detection Environment (AIDE) is one of those optional
packages. This requirement assumes the use of AIDE; however, a different tool
may be used if the requirements are met. Note that AIDE does not have a
configuration that will send a notification, so a cron job is recommended that
uses the mail application on the system to email the results of the file
integrity check.

```
New:
```
Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's Information System Security Manager (ISSM)/Information System Security Officer (ISSO) and System Administrators (SAs) must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item.

Notifications provided by information systems include messages to local computer consoles, and/or hardware indications, such as lights.

This capability must take into account operational requirements for availability for selecting an appropriate response. The organization may choose to shut down or restart the information system upon security function anomaly detection.

RHEL 8 comes with many optional software packages. A file integrity tool called Advanced Intrusion Detection Environment (AIDE) is one of those optional packages. This requirement assumes the use of AIDE; however, a different tool may be used if the requirements are met. Note that AIDE does not have a configuration that will send a notification, so a cron job is recommended that uses the mail application on the system to email the results of the file integrity check.



```
---
SV-230264:
Old:
```
Changes to any software components can have significant effects on the
overall security of the operating system. This requirement ensures the software
has not been tampered with and that it has been provided by a trusted vendor.

    Accordingly, patches, service packs, device drivers, or operating system
components must be signed with a certificate recognized and approved by the
organization.

    Verifying the authenticity of the software prior to installation validates
the integrity of the patch or upgrade received from a vendor. This verifies the
software has not been tampered with and that it has been provided by a trusted
vendor. Self-signed certificates are disallowed by this requirement. The
operating system should not have to verify the software again. This requirement
does not mandate DoD certificates for this purpose; however, the certificate
used to verify the software must be from an approved CA.

```
New:
```
Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization.

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This verifies the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.

```
---
SV-230265:
Old:
```
Changes to any software components can have significant effects on the
overall security of the operating system. This requirement ensures the software
has not been tampered with and that it has been provided by a trusted vendor.

    Accordingly, patches, service packs, device drivers, or operating system
components must be signed with a certificate recognized and approved by the
organization.

    Verifying the authenticity of the software prior to installation validates
the integrity of the patch or upgrade received from a vendor. This verifies the
software has not been tampered with and that it has been provided by a trusted
vendor. Self-signed certificates are disallowed by this requirement. The
operating system should not have to verify the software again. This requirement
does not mandate DoD certificates for this purpose; however, the certificate
used to verify the software must be from an approved CA.

```
New:
```
Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization.

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This verifies the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.

```
---
SV-230266:
Old:
```
Changes to any software components can have significant effects on the
overall security of the operating system. This requirement ensures the software
has not been tampered with and that it has been provided by a trusted vendor.

    Disabling kexec_load prevents an unsigned kernel image (that could be a
windows kernel or modified vulnerable kernel) from being loaded. Kexec can be
used subvert the entire secureboot process and should be avoided at all costs
especially since it can load unsigned kernel images.

```
New:
```
Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

Disabling kexec_load prevents an unsigned kernel image (that could be a windows kernel or modified vulnerable kernel) from being loaded. Kexec can be used subvert the entire secureboot process and should be avoided at all costs especially since it can load unsigned kernel images.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-230267:
Old:
```
Discretionary Access Control (DAC) is based on the notion that
individual users are "owners" of objects and therefore have discretion over
who should be authorized to access the object and in which mode (e.g., read or
write). Ownership is usually acquired as a consequence of creating the object
or via specified ownership assignment. DAC allows the owner to determine who
will have access to objects they control. An example of DAC includes
user-controlled file permissions.

    When discretionary access control policies are implemented, subjects are
not constrained with regard to what actions they can take with information for
which they have already been granted access. Thus, subjects that have been
granted access to information are not prevented from passing (i.e., the
subjects have the discretion to pass) the information to other subjects or
objects. A subject that is constrained in its operation by Mandatory Access
Control policies is still able to operate under the less rigorous constraints
of this requirement. Thus, while Mandatory Access Control imposes constraints
preventing a subject from passing information to another subject operating at a
different sensitivity level, this requirement permits the subject to pass the
information to any subject at the same sensitivity level. The policy is bounded
by the information system boundary. Once the information is passed outside the
control of the information system, additional means may be required to ensure
the constraints remain in effect. While the older, more traditional definitions
of discretionary access control require identity-based access control, that
limitation is not required for this use of discretionary access control.

    By enabling the fs.protected_symlinks kernel parameter, symbolic links are
permitted to be followed only when outside a sticky world-writable directory,
or when the UID of the link and follower match, or when the directory owner
matches the symlink's owner. Disallowing such symlinks helps mitigate
vulnerabilities based on insecure file system accessed by privileged programs,
avoiding an exploitation vector exploiting unsafe use of open() or creat().

```
New:
```
Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled file permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. The policy is bounded by the information system boundary. Once the information is passed outside the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.

By enabling the fs.protected_symlinks kernel parameter, symbolic links are permitted to be followed only when outside a sticky world-writable directory, or when the UID of the link and follower match, or when the directory owner matches the symlink's owner. Disallowing such symlinks helps mitigate vulnerabilities based on insecure file system accessed by privileged programs, avoiding an exploitation vector exploiting unsafe use of open() or creat().

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf



```
---
SV-230268:
Old:
```
Discretionary Access Control (DAC) is based on the notion that
individual users are "owners" of objects and therefore have discretion over
who should be authorized to access the object and in which mode (e.g., read or
write). Ownership is usually acquired as a consequence of creating the object
or via specified ownership assignment. DAC allows the owner to determine who
will have access to objects they control. An example of DAC includes
user-controlled file permissions.

    When discretionary access control policies are implemented, subjects are
not constrained with regard to what actions they can take with information for
which they have already been granted access. Thus, subjects that have been
granted access to information are not prevented from passing (i.e., the
subjects have the discretion to pass) the information to other subjects or
objects. A subject that is constrained in its operation by Mandatory Access
Control policies is still able to operate under the less rigorous constraints
of this requirement. Thus, while Mandatory Access Control imposes constraints
preventing a subject from passing information to another subject operating at a
different sensitivity level, this requirement permits the subject to pass the
information to any subject at the same sensitivity level. The policy is bounded
by the information system boundary. Once the information is passed outside the
control of the information system, additional means may be required to ensure
the constraints remain in effect. While the older, more traditional definitions
of discretionary access control require identity-based access control, that
limitation is not required for this use of discretionary access control.

    By enabling the fs.protected_hardlinks kernel parameter, users can no
longer create soft or hard links to files they do not own. Disallowing such
hardlinks mitigate vulnerabilities based on insecure file system accessed by
privileged programs, avoiding an exploitation vector exploiting unsafe use of
open() or creat().

```
New:
```
Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled file permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. The policy is bounded by the information system boundary. Once the information is passed outside the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.

By enabling the fs.protected_hardlinks kernel parameter, users can no longer create soft or hard links to files they do not own. Disallowing such hardlinks mitigate vulnerabilities based on insecure file system accessed by privileged programs, avoiding an exploitation vector exploiting unsafe use of open() or creat().

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf



```
---
SV-230269:
Old:
```
Preventing unauthorized information transfers mitigates the risk of
information, including encrypted representations of information, produced by
the actions of prior users/roles (or the actions of processes acting on behalf
of prior users/roles) from being available to any current users/roles (or
current processes) that obtain access to shared system resources (e.g.,
registers, main memory, hard disks) after those resources have been released
back to information systems. The control of information in shared resources is
also commonly referred to as object reuse and residual information protection.

    This requirement generally applies to the design of an information
technology product, but it can also apply to the configuration of particular
information system components that are, or use, such products. This can be
verified by acceptance/validation processes in DoD or other government agencies.

    There may be shared resources with configurable protections (e.g., files in
storage) that may be assessed on specific information system components.

    Restricting access to the kernel message buffer limits access to only root.
 This prevents attackers from gaining additional system information as a
non-privileged user.

```
New:
```
Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of particular information system components that are, or use, such products. This can be verified by acceptance/validation processes in DoD or other government agencies.

There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information system components.

Restricting access to the kernel message buffer limits access to only root. This prevents attackers from gaining additional system information as a non-privileged user.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-230270:
Old:
```
Preventing unauthorized information transfers mitigates the risk of
information, including encrypted representations of information, produced by
the actions of prior users/roles (or the actions of processes acting on behalf
of prior users/roles) from being available to any current users/roles (or
current processes) that obtain access to shared system resources (e.g.,
registers, main memory, hard disks) after those resources have been released
back to information systems. The control of information in shared resources is
also commonly referred to as object reuse and residual information protection.

    This requirement generally applies to the design of an information
technology product, but it can also apply to the configuration of particular
information system components that are, or use, such products. This can be
verified by acceptance/validation processes in DoD or other government agencies.

    There may be shared resources with configurable protections (e.g., files in
storage) that may be assessed on specific information system components.

    Setting the kernel.perf_event_paranoid kernel parameter to "2" prevents
attackers from gaining additional system information as a non-privileged user.

```
New:
```
Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of particular information system components that are, or use, such products. This can be verified by acceptance/validation processes in DoD or other government agencies.

There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information system components.

Setting the kernel.perf_event_paranoid kernel parameter to "2" prevents attackers from gaining additional system information as a non-privileged user.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-230271:
Old:
```
Without reauthentication, users may access resources or perform tasks
for which they do not have authorization.

    When operating systems provide the capability to escalate a functional
capability, it is critical the user reauthenticate.

```
New:
```
Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.



```
---
SV-230272:
Old:
```
Without reauthentication, users may access resources or perform tasks
for which they do not have authorization.

    When operating systems provide the capability to escalate a functional
capability, it is critical the user reauthenticate.

```
New:
```
Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.



```
---
SV-230273:
Old:
```
Using an authentication device, such as a DoD Common Access Card (CAC)
or token that is separate from the information system, ensures that even if the
information system is compromised, credentials stored on the authentication
device will not be affected.

    Multifactor solutions that require devices separate from information
systems gaining access include, for example, hardware tokens providing
time-based or challenge-response authenticators and smart cards such as the
U.S. Government Personal Identity Verification (PIV) card and the DoD CAC.

    A privileged account is defined as an information system account with
authorizations of a privileged user.

    Remote access is access to DoD nonpublic information systems by an
authorized user (or an information system) communicating through an external,
non-organization-controlled network. Remote access methods include, for
example, dial-up, broadband, and wireless.

    This requirement only applies to components where this is specific to the
function of the device or has the concept of an organizational user (e.g., VPN,
proxy capability). This does not apply to authentication for the purpose of
configuring the device itself (management).

```
New:
```
Using an authentication device, such as a DoD Common Access Card (CAC) or token that is separate from the information system, ensures that even if the information system is compromised, credentials stored on the authentication device will not be affected.

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification (PIV) card and the DoD CAC.

A privileged account is defined as an information system account with authorizations of a privileged user.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (management).

```
---
SV-230274:
Old:
```
Using an authentication device, such as a DoD Common Access Card (CAC)
or token that is separate from the information system, ensures that even if the
information system is compromised, credentials stored on the authentication
device will not be affected.

    Multifactor solutions that require devices separate from information
systems gaining access include, for example, hardware tokens providing
time-based or challenge-response authenticators and smart cards such as the
U.S. Government Personal Identity Verification (PIV) card and the DoD CAC.

    RHEL 8 includes multiple options for configuring certificate status
checking, but for this requirement focuses on the System Security Services
Daemon (SSSD). By default, sssd performs Online Certificate Status Protocol
(OCSP) checking and certificate verification using a sha256 digest function.

```
New:
```
Using an authentication device, such as a DoD Common Access Card (CAC) or token that is separate from the information system, ensures that even if the information system is compromised, credentials stored on the authentication device will not be affected.

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification (PIV) card and the DoD CAC.

RHEL 8 includes multiple options for configuring certificate status checking, but for this requirement focuses on the System Security Services Daemon (SSSD). By default, sssd performs Online Certificate Status Protocol (OCSP) checking and certificate verification using a sha256 digest function.



```
---
SV-230275:
Old:
```
The use of PIV credentials facilitates standardization and reduces the
risk of unauthorized access.

    The DoD has mandated the use of the Common Access Card (CAC) to support
identity management and personal authentication for systems covered under
Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a
primary component of layered protection for national security systems.

```
New:
```
The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

The DoD has mandated the use of the Common Access Card (CAC) to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.

```
---
SV-230276:
Old:
```
Some adversaries launch attacks with the intent of executing code in
non-executable regions of memory or in memory locations that are prohibited.
Security safeguards employed to protect memory include, for example, data
execution prevention and address space layout randomization. Data execution
prevention safeguards can be either hardware-enforced or software-enforced with
hardware providing the greater strength of mechanism.

    Examples of attacks are buffer overflow attacks.

```
New:
```
Some adversaries launch attacks with the intent of executing code in non-executable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can be either hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.

Examples of attacks are buffer overflow attacks.

```
---
SV-230277:
Old:
```
Some adversaries launch attacks with the intent of executing code in
non-executable regions of memory or in memory locations that are prohibited.
Security safeguards employed to protect memory include, for example, data
execution prevention and address space layout randomization. Data execution
prevention safeguards can be either hardware-enforced or software-enforced with
hardware providing the greater strength of mechanism.

    Poisoning writes an arbitrary value to freed pages, so any modification or
reference to that page after being freed or before being initialized will be
detected and prevented. This prevents many types of use-after-free
vulnerabilities at little performance cost. Also prevents leak of data and
detection of corrupted memory.

```
New:
```
Some adversaries launch attacks with the intent of executing code in non-executable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can be either hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.

Poisoning writes an arbitrary value to freed pages, so any modification or reference to that page after being freed or before being initialized will be detected and prevented. This prevents many types of use-after-free vulnerabilities at little performance cost. Also prevents leak of data and detection of corrupted memory.



```
---
SV-230278:
Old:
```
Syscalls are special routines in the Linux kernel, which userspace
applications ask to do privileged tasks.  Invoking a system call is an
expensive operation because the processor must interrupt the currently
executing task and switch context to kernel mode and then back to userspace
after the system call completes.  Virtual Syscalls map into user space a page
that contains some variables and the implementation of some system calls.  This
allows the system calls to be executed in userspace to alleviate the context
switching expense.

    Virtual Syscalls provide an opportunity of attack for a user who has
control of the return instruction pointer.  Disabling vsyscalls help to prevent
return oriented programming (ROP) attacks via buffer overflows and overruns. If
the system intends to run containers based on RHEL 6 components, then virtual
syscalls will need enabled so the components function properly.

```
New:
```
Syscalls are special routines in the Linux kernel, which userspace applications ask to do privileged tasks.  Invoking a system call is an expensive operation because the processor must interrupt the currently executing task and switch context to kernel mode and then back to userspace after the system call completes.  Virtual Syscalls map into user space a page that contains some variables and the implementation of some system calls.  This allows the system calls to be executed in userspace to alleviate the context switching expense.

Virtual Syscalls provide an opportunity of attack for a user who has control of the return instruction pointer.  Disabling vsyscalls help to prevent return oriented programming (ROP) attacks via buffer overflows and overruns. If the system intends to run containers based on RHEL 6 components, then virtual syscalls will need enabled so the components function properly.



```
---
SV-230279:
Old:
```
Some adversaries launch attacks with the intent of executing code in
non-executable regions of memory or in memory locations that are prohibited.
Security safeguards employed to protect memory include, for example, data
execution prevention and address space layout randomization. Data execution
prevention safeguards can be either hardware-enforced or software-enforced with
hardware providing the greater strength of mechanism.

    Poisoning writes an arbitrary value to freed pages, so any modification or
reference to that page after being freed or before being initialized will be
detected and prevented. This prevents many types of use-after-free
vulnerabilities at little performance cost. Also prevents leak of data and
detection of corrupted memory.

    SLAB objects are blocks of physically-contiguous memory.  SLUB is the
unqueued SLAB allocator.

```
New:
```
Some adversaries launch attacks with the intent of executing code in non-executable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can be either hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.

Poisoning writes an arbitrary value to freed pages, so any modification or reference to that page after being freed or before being initialized will be detected and prevented. This prevents many types of use-after-free vulnerabilities at little performance cost. Also prevents leak of data and detection of corrupted memory.

SLAB objects are blocks of physically-contiguous memory.  SLUB is the unqueued SLAB allocator.



```
---
SV-230280:
Old:
```
Some adversaries launch attacks with the intent of executing code in
non-executable regions of memory or in memory locations that are prohibited.
Security safeguards employed to protect memory include, for example, data
execution prevention and address space layout randomization. Data execution
prevention safeguards can be either hardware-enforced or software-enforced with
hardware providing the greater strength of mechanism.

    Examples of attacks are buffer overflow attacks.

```
New:
```
Some adversaries launch attacks with the intent of executing code in non-executable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can be either hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.

Examples of attacks are buffer overflow attacks.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-230281:
Old:
```
Previous versions of software components that are not removed from the
information system after updates have been installed may be exploited by
adversaries. Some information technology products may remove older versions of
software automatically from the information system.

```
New:
```
Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.

```
---
SV-230282:
Old:
```
Without verification of the security functions, security functions may
not operate correctly and the failure may go unnoticed. Security function is
defined as the hardware, software, and/or firmware of the information system
responsible for enforcing the system security policy and supporting the
isolation of code and data on which the protection is based. Security
functionality includes, but is not limited to, establishing system accounts,
configuring access authorizations (i.e., permissions, privileges), setting
events to be audited, and setting intrusion detection parameters.

    This requirement applies to operating systems performing security function
verification/testing and/or systems and environments that require this
functionality.

```
New:
```
Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.

```
---
SV-230283:
Old:
```
The "shosts.equiv" files are used to configure host-based
authentication for the system via SSH. Host-based authentication is not
sufficient for preventing unauthorized access to the system, as it does not
require interactive identification and authentication of a connection request,
or for the use of two-factor authentication.

```
New:
```
The "shosts.equiv" files are used to configure host-based authentication for the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.

```
---
SV-230284:
Old:
```
The ".shosts" files are used to configure host-based authentication
for individual users or the system via SSH. Host-based authentication is not
sufficient for preventing unauthorized access to the system, as it does not
require interactive identification and authentication of a connection request,
or for the use of two-factor authentication.

```
New:
```
The ".shosts" files are used to configure host-based authentication for individual users or the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.

```
---
SV-230285:
Old:
```
The most important characteristic of a random number generator is its randomness, namely its ability to deliver random numbers that are impossible to predict. Entropy in computer security is associated with the unpredictability of a source of randomness.  The random source with high entropy tends to achieve a uniform distribution of random values. Random number generators are one of the most important building blocks of cryptosystems.

The rngd service feeds random data from hardware device to kernel random device. Quality (nonpredictable) random number generation is important for several security functions (i.e., ciphers).

```
New:
```
The most important characteristic of a random number generator is its randomness, namely its ability to deliver random numbers that are impossible to predict. Entropy in computer security is associated with the unpredictability of a source of randomness.  The random source with high entropy tends to achieve a uniform distribution of random values. Random number generators are one of the most important building blocks of cryptosystems.  

The rngd service feeds random data from hardware device to kernel random device. Quality (nonpredictable) random number generation is important for several security functions (i.e., ciphers).

```
---
SV-230286:
Old:
```
If a public host key file is modified by an unauthorized user, the SSH
service may be compromised.

```
New:
```
If a public host key file is modified by an unauthorized user, the SSH service may be compromised.

```
---
SV-230287:
Old:
```
If an unauthorized user obtains the private SSH host key file, the
host could be impersonated.

```
New:
```
If an unauthorized user obtains the private SSH host key file, the host could be impersonated.

```
---
SV-230288:
Old:
```
If other users have access to modify user-specific SSH configuration
files, they may be able to log on to the system as another user.

```
New:
```
If other users have access to modify user-specific SSH configuration files, they may be able to log on to the system as another user.

```
---
SV-230290:
Old:
```
Configuring this setting for the SSH daemon provides additional
assurance that remote logon via SSH will require a password, even in the event
of misconfiguration elsewhere.

```
New:
```
Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.

```
---
SV-230291:
Old:
```
Configuring these settings for the SSH daemon provides additional
assurance that remote logon via SSH will not use unused methods of
authentication, even in the event of misconfiguration elsewhere.

```
New:
```
Configuring these settings for the SSH daemon provides additional assurance that remote logon via SSH will not use unused methods of authentication, even in the event of misconfiguration elsewhere.

```
---
SV-230292:
Old:
```
The use of separate file systems for different paths can protect the
system from failures resulting from a file system becoming full or failing.

```
New:
```
The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.

```
---
SV-230293:
Old:
```
The use of separate file systems for different paths can protect the
system from failures resulting from a file system becoming full or failing.

```
New:
```
The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.

```
---
SV-230294:
Old:
```
The use of separate file systems for different paths can protect the
system from failures resulting from a file system becoming full or failing.

```
New:
```
The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.

```
---
SV-230295:
Old:
```
The use of separate file systems for different paths can protect the
system from failures resulting from a file system becoming full or failing.

```
New:
```
The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.

```
---
SV-230296:
Old:
```
Even though the communications channel may be encrypted, an additional
layer of security is gained by extending the policy of not logging on directly
as root. In addition, logging on with a user-specific account provides
individual accountability of actions performed on the system.

```
New:
```
Even though the communications channel may be encrypted, an additional layer of security is gained by extending the policy of not logging on directly as root. In addition, logging on with a user-specific account provides individual accountability of actions performed on the system.

```
---
SV-230298:
Old:
```
Configuring RHEL 8 to implement organization-wide security
implementation guides and security checklists ensures compliance with federal
standards and establishes a common security baseline across the DoD that
reflects the most restrictive security posture consistent with operational
requirements.

    Configuration settings are the set of parameters that can be changed in
hardware, software, or firmware components of the system that affect the
security posture and/or functionality of the system. Security-related
parameters are those parameters impacting the security state of the system,
including the parameters required to satisfy other security control
requirements. Security-related parameters include, for example: registry
settings; account, file, directory permission settings; and settings for
functions, ports, protocols, services, and remote connections.

```
New:
```
Configuring RHEL 8 to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across the DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.

```
---
SV-230299:
Old:
```
The "nosuid" mount option causes the system not to execute
"setuid" and "setgid" files with owner privileges. This option must be used
for mounting any file system not containing approved "setuid" and "setguid"
files. Executing files from untrusted file systems increases the opportunity
for unprivileged users to attain unauthorized administrative access.

```
New:
```
The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230300:
Old:
```
The "nosuid" mount option causes the system not to execute
"setuid" and "setgid" files with owner privileges. This option must be used
for mounting any file system not containing approved "setuid" and "setguid"
files. Executing files from untrusted file systems increases the opportunity
for unprivileged users to attain unauthorized administrative access.

```
New:
```
The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230301:
Old:
```
The "nodev" mount option causes the system to not interpret
character or block special devices. Executing character or block special
devices from untrusted file systems increases the opportunity for unprivileged
users to attain unauthorized administrative access.  The only legitimate
location for device files is the /dev directory located on the root partition.

```
New:
```
The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.  The only legitimate location for device files is the /dev directory located on the root partition.

```
---
SV-230302:
Old:
```
The "noexec" mount option causes the system not to execute binary
files. This option must be used for mounting any file system not containing
approved binary files, as they may be incompatible. Executing files from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access.

```
New:
```
The "noexec" mount option causes the system not to execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230303:
Old:
```
The "nodev" mount option causes the system not to interpret
character or block special devices. Executing character or block special
devices from untrusted file systems increases the opportunity for unprivileged
users to attain unauthorized administrative access.

```
New:
```
The "nodev" mount option causes the system not to interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230304:
Old:
```
The "noexec" mount option causes the system not to execute binary
files. This option must be used for mounting any file system not containing
approved binary files, as they may be incompatible. Executing files from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access.

```
New:
```
The "noexec" mount option causes the system not to execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230305:
Old:
```
The "nosuid" mount option causes the system not to execute
"setuid" and "setgid" files with owner privileges. This option must be used
for mounting any file system not containing approved "setuid" and "setguid"
files. Executing files from untrusted file systems increases the opportunity
for unprivileged users to attain unauthorized administrative access.

```
New:
```
The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230306:
Old:
```
The "noexec" mount option causes the system not to execute binary
files. This option must be used for mounting any file system not containing
approved binary as they may be incompatible. Executing files from untrusted
file systems increases the opportunity for unprivileged users to attain
unauthorized administrative access.

```
New:
```
The "noexec" mount option causes the system not to execute binary files. This option must be used for mounting any file system not containing approved binary as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230307:
Old:
```
The "nodev" mount option causes the system to not interpret
character or block special devices. Executing character or block special
devices from untrusted file systems increases the opportunity for unprivileged
users to attain unauthorized administrative access.

```
New:
```
The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230308:
Old:
```
The "nosuid" mount option causes the system not to execute
"setuid" and "setgid" files with owner privileges. This option must be used
for mounting any file system not containing approved "setuid" and "setguid"
files. Executing files from untrusted file systems increases the opportunity
for unprivileged users to attain unauthorized administrative access.

```
New:
```
The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230309:
Old:
```
If user start-up files execute world-writable programs, especially in
unprotected directories, they could be maliciously modified to destroy user
files or otherwise compromise the system at the user level. If the system is
compromised at the user level, it is easier to elevate privileges to eventually
compromise the system at the root and network level.

```
New:
```
If user start-up files execute world-writable programs, especially in unprotected directories, they could be maliciously modified to destroy user files or otherwise compromise the system at the user level. If the system is compromised at the user level, it is easier to elevate privileges to eventually compromise the system at the root and network level.

```
---
SV-230310:
Old:
```
Kernel core dumps may contain the full contents of system memory at
the time of the crash. Kernel core dumps may consume a considerable amount of
disk space and may result in denial of service by exhausting the available
space on the target file system partition.

    RHEL 8 installation media presents the option to enable or disable the
kdump service at the time of system installation.

```
New:
```
Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps may consume a considerable amount of disk space and may result in denial of service by exhausting the available space on the target file system partition.

RHEL 8 installation media presents the option to enable or disable the kdump service at the time of system installation.

```
---
SV-230311:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-230312:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    A core dump includes a memory image taken at the time the operating system
terminates an application. The memory image could contain sensitive data and is
generally useful only for developers trying to debug problems.

    When the kernel invokes systemd-coredumpt to handle a core dump, it runs in
privileged mode, and will connect to the socket created by the
systemd-coredump.socket unit. This, in turn,  will spawn an unprivileged
systemd-coredump@.service instance to process the core dump.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems.

When the kernel invokes systemd-coredumpt to handle a core dump, it runs in privileged mode, and will connect to the socket created by the systemd-coredump.socket unit. This, in turn,  will spawn an unprivileged systemd-coredump@.service instance to process the core dump.

```
---
SV-230313:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    A core dump includes a memory image taken at the time the operating system
terminates an application. The memory image could contain sensitive data and is
generally useful only for developers trying to debug problems.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems.

```
---
SV-230314:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    A core dump includes a memory image taken at the time the operating system
terminates an application. The memory image could contain sensitive data and is
generally useful only for developers trying to debug problems.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems.

```
---
SV-230315:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    A core dump includes a memory image taken at the time the operating system
terminates an application. The memory image could contain sensitive data and is
generally useful only for developers trying to debug problems.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems.

```
---
SV-230316:
Old:
```
To provide availability for name resolution services, multiple
redundant name servers are mandated. A failure in name resolution could lead to
the failure of security functions requiring name resolution, which may include
time synchronization, centralized authentication, and remote system logging.

```
New:
```
To provide availability for name resolution services, multiple redundant name servers are mandated. A failure in name resolution could lead to the failure of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.

```
---
SV-230317:
Old:
```
The executable search path (typically the PATH environment variable)
contains a list of directories for the shell to search to find executables. If
this path includes the current working directory (other than the user's home
directory), executables in these directories may be executed instead of system
commands. This variable is formatted as a colon-separated list of directories.
If there is an empty entry, such as a leading or trailing colon or two
consecutive colons, this is interpreted as the current working directory. If
deviations from the default system search path for the local interactive user
are required, they must be documented with the Information System Security
Officer (ISSO).

```
New:
```
The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory (other than the user's home directory), executables in these directories may be executed instead of system commands. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon or two consecutive colons, this is interpreted as the current working directory. If deviations from the default system search path for the local interactive user are required, they must be documented with the Information System Security Officer (ISSO).

```
---
SV-230318:
Old:
```
If a world-writable directory is not owned by root, sys, bin, or an
application User Identifier (UID), unauthorized users may be able to modify
files created by others.

    The only authorized public directories are those temporary directories
supplied with the system or those designed to be temporary file repositories.
The setting is normally reserved for directories used by the system and by
users for temporary file storage, (e.g., /tmp), and for directories requiring
global read/write access.

```
New:
```
If a world-writable directory is not owned by root, sys, bin, or an application User Identifier (UID), unauthorized users may be able to modify files created by others.

The only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage, (e.g., /tmp), and for directories requiring global read/write access.

```
---
SV-230319:
Old:
```
If a world-writable directory is not group-owned by root, sys, bin, or
an application Group Identifier (GID), unauthorized users may be able to modify
files created by others.

    The only authorized public directories are those temporary directories
supplied with the system or those designed to be temporary file repositories.
The setting is normally reserved for directories used by the system and by
users for temporary file storage, (e.g., /tmp), and for directories requiring
global read/write access.

```
New:
```
If a world-writable directory is not group-owned by root, sys, bin, or an application Group Identifier (GID), unauthorized users may be able to modify files created by others.

The only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage, (e.g., /tmp), and for directories requiring global read/write access.

```
---
SV-230320:
Old:
```
If local interactive users are not assigned a valid home directory,
there is no place for the storage and control of files they should own.

```
New:
```
If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.

```
---
SV-230321:
Old:
```
Excessive permissions on local interactive user home directories may
allow unauthorized access to user files by other users.

```
New:
```
Excessive permissions on local interactive user home directories may allow unauthorized access to user files by other users.

```
---
SV-230322:
Old:
```
If the Group Identifier (GID) of a local interactive user’s home
directory is not the same as the primary GID of the user, this would allow
unauthorized access to the user’s files, and users that share the same group
may not be able to access files that they legitimately should.

```
New:
```
If the Group Identifier (GID) of a local interactive user’s home directory is not the same as the primary GID of the user, this would allow unauthorized access to the user’s files, and users that share the same group may not be able to access files that they legitimately should.

```
---
SV-230323:
Old:
```
If a local interactive user has a home directory defined that does not
exist, the user may be given access to the "/" directory as the current
working directory upon logon. This could create a denial of service because the
user would not be able to access their logon configuration files, and it may
give them visibility to system files they normally would not be able to access.

```
New:
```
If a local interactive user has a home directory defined that does not exist, the user may be given access to the "/" directory as the current working directory upon logon. This could create a denial of service because the user would not be able to access their logon configuration files, and it may give them visibility to system files they normally would not be able to access.

```
---
SV-230324:
Old:
```
If local interactive users are not assigned a valid home directory,
there is no place for the storage and control of files they should own.

```
New:
```
If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.

```
---
SV-230325:
Old:
```
Local initialization files are used to configure the user's shell
environment upon logon. Malicious modification of these files could compromise
accounts upon logon.

```
New:
```
Local initialization files are used to configure the user's shell environment upon logon. Malicious modification of these files could compromise accounts upon logon.

```
---
SV-230326:
Old:
```
Unowned files and directories may be unintentionally inherited if a
user is assigned the same User Identifier "UID" as the UID of the un-owned
files.

```
New:
```
Unowned files and directories may be unintentionally inherited if a user is assigned the same User Identifier "UID" as the UID of the un-owned files.

```
---
SV-230327:
Old:
```
Files without a valid group owner may be unintentionally inherited if
a group is assigned the same Group Identifier (GID) as the GID of the files
without a valid group owner.

```
New:
```
Files without a valid group owner may be unintentionally inherited if a group is assigned the same Group Identifier (GID) as the GID of the files without a valid group owner.

```
---
SV-230328:
Old:
```
The use of separate file systems for different paths can protect the
system from failures resulting from a file system becoming full or failing.

```
New:
```
The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.

```
---
SV-230329:
Old:
```
Failure to restrict system access to authenticated users negatively
impacts operating system security.

```
New:
```
Failure to restrict system access to authenticated users negatively impacts operating system security.

```
---
SV-230330:
Old:
```
SSH environment options potentially allow users to bypass access
restriction in some configurations.

```
New:
```
SSH environment options potentially allow users to bypass access restriction in some configurations.

```
---
SV-230331:
Old:
```
If temporary user accounts remain active when no longer needed or for
an excessive period, these accounts may be used to gain unauthorized access. To
mitigate this risk, automated termination of all temporary accounts must be set
upon account creation.

    Temporary accounts are established as part of normal account activation
procedures when there is a need for short-term accounts without the demand for
immediacy in account activation.

    If temporary accounts are used, RHEL 8 must be configured to automatically
terminate these types of accounts after a DoD-defined time period of 72 hours.

    To address access requirements, many RHEL 8 operating systems may be
integrated with enterprise-level authentication/access mechanisms that meet or
exceed access control policy requirements.

```
New:
```
If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation.

Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation.

If temporary accounts are used, RHEL 8 must be configured to automatically terminate these types of accounts after a DoD-defined time period of 72 hours.

To address access requirements, many RHEL 8 operating systems may be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements.

```
---
SV-230332:
Old:
```
By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account.

    RHEL 8 can utilize the "pam_faillock.so" for this purpose. Note that
manual changes to the listed files may be overwritten by the "authselect"
program.

    From "Pam_Faillock" man pages: Note that the default directory that
"pam_faillock" uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the "dir" option.

```
New:
```
By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

RHEL 8 can utilize the "pam_faillock.so" for this purpose. Note that manual changes to the listed files may be overwritten by the "authselect" program.

From "Pam_Faillock" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable a different tally directory must be set with the "dir" option.



```
---
SV-230333:
Old:
```
By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account.

    In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to
centralize the configuration of the pam_faillock.so module.  Also introduced is
a "local_users_only" option that will only track failed user authentication
attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP,
etc.) users to allow the centralized platform to solely manage user lockout.

    From "faillock.conf" man pages: Note that the default directory that
"pam_faillock" uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the "dir" option.

```
New:
```
By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to centralize the configuration of the pam_faillock.so module.  Also introduced is a "local_users_only" option that will only track failed user authentication attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP, etc.) users to allow the centralized platform to solely manage user lockout.

From "faillock.conf" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable a different tally directory must be set with the "dir" option.



```
---
SV-230334:
Old:
```
By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account.

    RHEL 8 can utilize the "pam_faillock.so" for this purpose. Note that
manual changes to the listed files may be overwritten by the "authselect"
program.

    From "Pam_Faillock" man pages: Note that the default directory that
"pam_faillock" uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the "dir" option.

```
New:
```
By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

RHEL 8 can utilize the "pam_faillock.so" for this purpose. Note that manual changes to the listed files may be overwritten by the "authselect" program.

From "Pam_Faillock" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable a different tally directory must be set with the "dir" option.



```
---
SV-230335:
Old:
```
By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account.

    In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to
centralize the configuration of the pam_faillock.so module.  Also introduced is
a "local_users_only" option that will only track failed user authentication
attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP,
etc.) users to allow the centralized platform to solely manage user lockout.

    From "faillock.conf" man pages: Note that the default directory that
"pam_faillock" uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the "dir" option.

```
New:
```
By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to centralize the configuration of the pam_faillock.so module.  Also introduced is a "local_users_only" option that will only track failed user authentication attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP, etc.) users to allow the centralized platform to solely manage user lockout.

From "faillock.conf" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable a different tally directory must be set with the "dir" option.



```
---
SV-230336:
Old:
```
By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account.

    RHEL 8 can utilize the "pam_faillock.so" for this purpose. Note that
manual changes to the listed files may be overwritten by the "authselect"
program.

    From "Pam_Faillock" man pages: Note that the default directory that
"pam_faillock" uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the "dir" option.

```
New:
```
By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

RHEL 8 can utilize the "pam_faillock.so" for this purpose. Note that manual changes to the listed files may be overwritten by the "authselect" program.

From "Pam_Faillock" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable a different tally directory must be set with the "dir" option.



```
---
SV-230337:
Old:
```
By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account.

    In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to
centralize the configuration of the pam_faillock.so module.  Also introduced is
a "local_users_only" option that will only track failed user authentication
attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP,
etc.) users to allow the centralized platform to solely manage user lockout.

    From "faillock.conf" man pages: Note that the default directory that
"pam_faillock" uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the "dir" option.

```
New:
```
By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to centralize the configuration of the pam_faillock.so module.  Also introduced is a "local_users_only" option that will only track failed user authentication attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP, etc.) users to allow the centralized platform to solely manage user lockout.

From "faillock.conf" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable a different tally directory must be set with the "dir" option.



```
---
SV-230338:
Old:
```
By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account.

    RHEL 8 can utilize the "pam_faillock.so" for this purpose. Note that
manual changes to the listed files may be overwritten by the "authselect"
program.

    From "Pam_Faillock" man pages: Note that the default directory that
"pam_faillock" uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the "dir" option.

```
New:
```
By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

RHEL 8 can utilize the "pam_faillock.so" for this purpose. Note that manual changes to the listed files may be overwritten by the "authselect" program.

From "Pam_Faillock" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable a different tally directory must be set with the "dir" option.



```
---
SV-230339:
Old:
```
By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account.

    In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to
centralize the configuration of the pam_faillock.so module.  Also introduced is
a "local_users_only" option that will only track failed user authentication
attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP,
etc.) users to allow the centralized platform to solely manage user lockout.

    From "faillock.conf" man pages: Note that the default directory that
"pam_faillock" uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the "dir" option.

```
New:
```
By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to centralize the configuration of the pam_faillock.so module.  Also introduced is a "local_users_only" option that will only track failed user authentication attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP, etc.) users to allow the centralized platform to solely manage user lockout.

From "faillock.conf" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable a different tally directory must be set with the "dir" option.



```
---
SV-230340:
Old:
```
By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account.

    RHEL 8 can utilize the "pam_faillock.so" for this purpose. Note that
manual changes to the listed files may be overwritten by the "authselect"
program.

    From "Pam_Faillock" man pages: Note that the default directory that
"pam_faillock" uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the "dir" option.

```
New:
```
By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

RHEL 8 can utilize the "pam_faillock.so" for this purpose. Note that manual changes to the listed files may be overwritten by the "authselect" program.

From "Pam_Faillock" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable a different tally directory must be set with the "dir" option.



```
---
SV-230341:
Old:
```
By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account.

    In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to
centralize the configuration of the pam_faillock.so module.  Also introduced is
a "local_users_only" option that will only track failed user authentication
attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP,
etc.) users to allow the centralized platform to solely manage user lockout.

    From "faillock.conf" man pages: Note that the default directory that
"pam_faillock" uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the "dir" option.

```
New:
```
By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to centralize the configuration of the pam_faillock.so module.  Also introduced is a "local_users_only" option that will only track failed user authentication attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP, etc.) users to allow the centralized platform to solely manage user lockout.

From "faillock.conf" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable a different tally directory must be set with the "dir" option.



```
---
SV-230342:
Old:
```
By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account.

    RHEL 8 can utilize the "pam_faillock.so" for this purpose. Note that
manual changes to the listed files may be overwritten by the "authselect"
program.

    From "Pam_Faillock" man pages: Note that the default directory that
"pam_faillock" uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the "dir" option.

    In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to
centralize the configuration of the pam_faillock.so module. Also introduced is
a "local_users_only" option that will only track failed user authentication
attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP,
etc.) users to allow the centralized platform to solely manage user lockout.

```
New:
```
By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

RHEL 8 can utilize the "pam_faillock.so" for this purpose. Note that manual changes to the listed files may be overwritten by the "authselect" program.

From "Pam_Faillock" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable a different tally directory must be set with the "dir" option.

In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to centralize the configuration of the pam_faillock.so module. Also introduced is a "local_users_only" option that will only track failed user authentication attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP, etc.) users to allow the centralized platform to solely manage user lockout.



```
---
SV-230343:
Old:
```
By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account.

    In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to
centralize the configuration of the pam_faillock.so module.  Also introduced is
a "local_users_only" option that will only track failed user authentication
attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP,
etc.) users to allow the centralized platform to solely manage user lockout.

    From "faillock.conf" man pages: Note that the default directory that
"pam_faillock" uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the "dir" option.

```
New:
```
By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to centralize the configuration of the pam_faillock.so module.  Also introduced is a "local_users_only" option that will only track failed user authentication attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP, etc.) users to allow the centralized platform to solely manage user lockout.

From "faillock.conf" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable a different tally directory must be set with the "dir" option.



```
---
SV-230344:
Old:
```
By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account.

    RHEL 8 can utilize the "pam_faillock.so" for this purpose. Note that
manual changes to the listed files may be overwritten by the "authselect"
program.

    From "Pam_Faillock" man pages: Note that the default directory that
"pam_faillock" uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the "dir" option.

    In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to
centralize the configuration of the pam_faillock.so module. Also introduced is
a "local_users_only" option that will only track failed user authentication
attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP,
etc.) users to allow the centralized platform to solely manage user lockout.

```
New:
```
By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

RHEL 8 can utilize the "pam_faillock.so" for this purpose. Note that manual changes to the listed files may be overwritten by the "authselect" program.

From "Pam_Faillock" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable a different tally directory must be set with the "dir" option.

In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to centralize the configuration of the pam_faillock.so module. Also introduced is a "local_users_only" option that will only track failed user authentication attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP, etc.) users to allow the centralized platform to solely manage user lockout.



```
---
SV-230345:
Old:
```
By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account.

    In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to
centralize the configuration of the pam_faillock.so module.  Also introduced is
a "local_users_only" option that will only track failed user authentication
attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP,
etc.) users to allow the centralized platform to solely manage user lockout.

    From "faillock.conf" man pages: Note that the default directory that
"pam_faillock" uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the "dir" option.

```
New:
```
By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to centralize the configuration of the pam_faillock.so module.  Also introduced is a "local_users_only" option that will only track failed user authentication attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP, etc.) users to allow the centralized platform to solely manage user lockout.

From "faillock.conf" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable a different tally directory must be set with the "dir" option.



```
---
SV-230346:
Old:
```
Operating system management includes the ability to control the number
of users and user sessions that utilize an operating system. Limiting the
number of allowed users and sessions per user is helpful in reducing the risks
related to DoS attacks.

    This requirement addresses concurrent sessions for information system
accounts and does not address concurrent sessions by single users via multiple
system accounts. The maximum number of concurrent sessions should be defined
based on mission needs and the operational environment for each system.

```
New:
```
Operating system management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to DoS attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based on mission needs and the operational environment for each system.

```
---
SV-230347:
Old:
```
A session lock is a temporary action taken when a user stops work and
moves away from the immediate physical vicinity of the information system but
does not want to log out because of the temporary nature of the absence.

    The session lock is implemented at the point where session activity can be
determined.

    Regardless of where the session lock is determined and implemented, once
invoked, the session lock must remain in place until the user reauthenticates.
No other activity aside from reauthentication must unlock the system.

```
New:
```
A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined.

Regardless of where the session lock is determined and implemented, once invoked, the session lock must remain in place until the user reauthenticates. No other activity aside from reauthentication must unlock the system.



```
---
SV-230348:
Old:
```
A session lock is a temporary action taken when a user stops work and
moves away from the immediate physical vicinity of the information system but
does not want to log out because of the temporary nature of the absence.

    The session lock is implemented at the point where session activity can be
determined. Rather than be forced to wait for a period of time to expire before
the user session can be locked, RHEL 8 needs to provide users with the ability
to manually invoke a session lock so users can secure their session if it is
necessary to temporarily vacate the immediate physical vicinity.

    Tmux is a terminal multiplexer that enables a number of terminals to be
created, accessed, and controlled from a single screen.  Red Hat endorses tmux
as the recommended session controlling package.

```
New:
```
A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, RHEL 8 needs to provide users with the ability to manually invoke a session lock so users can secure their session if it is necessary to temporarily vacate the immediate physical vicinity.

Tmux is a terminal multiplexer that enables a number of terminals to be created, accessed, and controlled from a single screen.  Red Hat endorses tmux as the recommended session controlling package.



```
---
SV-230349:
Old:
```
A session lock is a temporary action taken when a user stops work and
moves away from the immediate physical vicinity of the information system but
does not want to log out because of the temporary nature of the absence.

    The session lock is implemented at the point where session activity can be
determined. Rather than be forced to wait for a period of time to expire before
the user session can be locked, RHEL 8 needs to provide users with the ability
to manually invoke a session lock so users can secure their session if it is
necessary to temporarily vacate the immediate physical vicinity.

    Tmux is a terminal multiplexer that enables a number of terminals to be
created, accessed, and controlled from a single screen.  Red Hat endorses tmux
as the recommended session controlling package.

```
New:
```
Tmux is a terminal multiplexer that enables a number of terminals to be created, accessed, and controlled from a single screen. Red Hat endorses tmux as the recommended session controlling package.



```
---
SV-230350:
Old:
```
A session lock is a temporary action taken when a user stops work and
moves away from the immediate physical vicinity of the information system but
does not want to log out because of the temporary nature of the absence.

    The session lock is implemented at the point where session activity can be
determined. Rather than be forced to wait for a period of time to expire before
the user session can be locked, RHEL 8 needs to provide users with the ability
to manually invoke a session lock so users can secure their session if it is
necessary to temporarily vacate the immediate physical vicinity.

    Tmux is a terminal multiplexer that enables a number of terminals to be
created, accessed, and controlled from a single screen.  Red Hat endorses tmux
as the recommended session controlling package.

```
New:
```
A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, RHEL 8 needs to provide users with the ability to manually invoke a session lock so users can secure their session if it is necessary to temporarily vacate the immediate physical vicinity.

Tmux is a terminal multiplexer that enables a number of terminals to be created, accessed, and controlled from a single screen.  Red Hat endorses tmux as the recommended session controlling package.



```
---
SV-230351:
Old:
```
A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, RHEL 8 needs to provide users with the ability to manually invoke a session lock so users can secure their session if it is necessary to temporarily vacate the immediate physical vicinity.

```
New:
```
A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, RHEL 8 needs to provide users with the ability to manually invoke a session lock so users can secure their session if it is necessary to temporarily vacate the immediate physical vicinity.



```
---
SV-230352:
Old:
```
A session lock is a temporary action taken when a user stops work and
moves away from the immediate physical vicinity of the information system but
does not want to log out because of the temporary nature of the absence.

    The session lock is implemented at the point where session activity can be
determined. Rather than be forced to wait for a period of time to expire before
the user session can be locked, RHEL 8 needs to provide users with the ability
to manually invoke a session lock so users can secure their session if it is
necessary to temporarily vacate the immediate physical vicinity.

```
New:
```
A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, RHEL 8 needs to provide users with the ability to manually invoke a session lock so users can secure their session if it is necessary to temporarily vacate the immediate physical vicinity.



```
---
SV-230353:
Old:
```
Terminating an idle session within a short time period reduces the
window of opportunity for unauthorized personnel to take control of a
management session enabled on the console or console port that has been left
unattended. In addition, quickly terminating an idle session will also free up
resources committed by the managed network element.

    Terminating network connections associated with communications sessions
includes, for example, de-allocating associated TCP/IP address/port pairs at
the operating system level and de-allocating networking assignments at the
application level if multiple application sessions are using a single operating
system-level network connection. This does not mean the operating system
terminates all sessions or network access; it only ends the inactive session
and releases the resources associated with that session.

```
New:
```
Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.



```
---
SV-230354:
Old:
```
A session time-out lock is a temporary action taken when a user stops
work and moves away from the immediate physical vicinity of the information
system but does not log out because of the temporary nature of the absence.
Rather than relying on the user to manually lock their operating system session
prior to vacating the vicinity, operating systems need to be able to identify
when a user's session has idled and take action to initiate the session lock.

    The session lock is implemented at the point where session activity can be
determined and/or controlled.

    Implementing session settings will have little value if a user is able to
manipulate these settings from the defaults prescribed in the other
requirements of this implementation guide.

    Locking these settings from non-privileged users is crucial to maintaining
a protected baseline.

```
New:
```
A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled.

Implementing session settings will have little value if a user is able to manipulate these settings from the defaults prescribed in the other requirements of this implementation guide.

Locking these settings from non-privileged users is crucial to maintaining a protected baseline.



```
---
SV-230355:
Old:
```
Without mapping the certificate used to authenticate to the user
account, the ability to determine the identity of the individual user or group
will not be available for forensic analysis.

    There are various methods of mapping certificates to user/group accounts
for RHEL 8. For the purposes of this requirement, the check and fix will
account for Active Directory mapping. Some of the other possible methods
include joining the system to a domain and utilizing a Red Hat idM server, or a
local system mapping, where the system is not part of a domain.

```
New:
```
Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.

There are various methods of mapping certificates to user/group accounts for RHEL 8. For the purposes of this requirement, the check and fix will account for Active Directory mapping. Some of the other possible methods include joining the system to a domain and utilizing a Red Hat idM server, or a local system mapping, where the system is not part of a domain.

```
---
SV-230357:
Old:
```
Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks.

    Password complexity is one factor of several that determines how long it
takes to crack a password. The more complex the password, the greater the
number of possible combinations that need to be tested before the password is
compromised.

    RHEL 8 utilizes pwquality as a mechanism to enforce password complexity.
Note that in order to require uppercase characters, without degrading the
"minlen" value, the credit value must be expressed as a negative number in
"/etc/security/pwquality.conf".

```
New:
```
Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

RHEL 8 utilizes pwquality as a mechanism to enforce password complexity. Note that in order to require uppercase characters, without degrading the "minlen" value, the credit value must be expressed as a negative number in "/etc/security/pwquality.conf".

```
---
SV-230358:
Old:
```
Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks.

    Password complexity is one factor of several that determines how long it
takes to crack a password. The more complex the password, the greater the
number of possible combinations that need to be tested before the password is
compromised.

    RHEL 8 utilizes pwquality as a mechanism to enforce password complexity.
Note that in order to require lower-case characters without degrading the
"minlen" value, the credit value must be expressed as a negative number in
"/etc/security/pwquality.conf".

```
New:
```
Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

RHEL 8 utilizes pwquality as a mechanism to enforce password complexity. Note that in order to require lower-case characters without degrading the "minlen" value, the credit value must be expressed as a negative number in "/etc/security/pwquality.conf".

```
---
SV-230359:
Old:
```
Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks.

    Password complexity is one factor of several that determines how long it
takes to crack a password. The more complex the password, the greater the
number of possible combinations that need to be tested before the password is
compromised.

    RHEL 8 utilizes "pwquality" as a mechanism to enforce password
complexity. Note that in order to require numeric characters, without degrading
the minlen value, the credit value must be expressed as a negative number in
"/etc/security/pwquality.conf".

```
New:
```
Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

RHEL 8 utilizes "pwquality" as a mechanism to enforce password complexity. Note that in order to require numeric characters, without degrading the minlen value, the credit value must be expressed as a negative number in "/etc/security/pwquality.conf".

```
---
SV-230360:
Old:
```
Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks.

    Password complexity is one factor of several that determines how long it
takes to crack a password. The more complex the password, the greater the
number of possible combinations that need to be tested before the password is
compromised.

    RHEL 8 utilizes "pwquality" as a mechanism to enforce password
complexity. The "maxclassrepeat" option sets the maximum number of allowed
same consecutive characters in the same class in the new password.

```
New:
```
Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

RHEL 8 utilizes "pwquality" as a mechanism to enforce password complexity. The "maxclassrepeat" option sets the maximum number of allowed same consecutive characters in the same class in the new password.

```
---
SV-230361:
Old:
```
Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks.

    Password complexity is one factor of several that determines how long it
takes to crack a password. The more complex the password, the greater the
number of possible combinations that need to be tested before the password is
compromised.

    RHEL 8 utilizes "pwquality" as a mechanism to enforce password
complexity. The "maxrepeat" option sets the maximum number of allowed same
consecutive characters in a new password.

```
New:
```
Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

RHEL 8 utilizes "pwquality" as a mechanism to enforce password complexity. The "maxrepeat" option sets the maximum number of allowed same consecutive characters in a new password.

```
---
SV-230362:
Old:
```
Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks.

    Password complexity is one factor of several that determines how long it
takes to crack a password. The more complex the password, the greater the
number of possible combinations that need to be tested before the password is
compromised.

    RHEL 8 utilizes "pwquality" as a mechanism to enforce password
complexity. The "minclass" option sets the minimum number of required classes
of characters for the new password (digits, uppercase, lowercase, others).

```
New:
```
Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

RHEL 8 utilizes "pwquality" as a mechanism to enforce password complexity. The "minclass" option sets the minimum number of required classes of characters for the new password (digits, uppercase, lowercase, others).

```
---
SV-230363:
Old:
```
Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks.

    Password complexity is one factor of several that determines how long it
takes to crack a password. The more complex the password, the greater the
number of possible combinations that need to be tested before the password is
compromised.

    RHEL 8 utilizes "pwquality" as a mechanism to enforce password
complexity. The "difok" option sets the number of characters in a password
that must not be present in the old password.

```
New:
```
Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

RHEL 8 utilizes "pwquality" as a mechanism to enforce password complexity. The "difok" option sets the number of characters in a password that must not be present in the old password.

```
---
SV-230364:
Old:
```
Enforcing a minimum password lifetime helps to prevent repeated
password changes to defeat the password reuse or history enforcement
requirement. If users are allowed to immediately and continually change their
password, the password could be repeatedly changed in a short period of time to
defeat the organization's policy regarding password reuse.

```
New:
```
Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse.

```
---
SV-230365:
Old:
```
Enforcing a minimum password lifetime helps to prevent repeated
password changes to defeat the password reuse or history enforcement
requirement. If users are allowed to immediately and continually change their
password, the password could be repeatedly changed in a short period of time to
defeat the organization's policy regarding password reuse.

```
New:
```
Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse.

```
---
SV-230366:
Old:
```
Any password, no matter how complex, can eventually be cracked.
Therefore, passwords need to be changed periodically. If RHEL 8 does not limit
the lifetime of passwords and force users to change their passwords, there is
the risk that RHEL 8 passwords could be compromised.

```
New:
```
Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If RHEL 8 does not limit the lifetime of passwords and force users to change their passwords, there is the risk that RHEL 8 passwords could be compromised.

```
---
SV-230367:
Old:
```
Any password, no matter how complex, can eventually be cracked.
Therefore, passwords need to be changed periodically. If RHEL 8 does not limit
the lifetime of passwords and force users to change their passwords, there is
the risk that RHEL 8 passwords could be compromised.

```
New:
```
Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If RHEL 8 does not limit the lifetime of passwords and force users to change their passwords, there is the risk that RHEL 8 passwords could be compromised.

```
---
SV-230368:
Old:
```
Password complexity, or strength, is a measure of the effectiveness of
a password in resisting attempts at guessing and brute-force attacks. If the
information system or application allows the user to reuse their password
consecutively when that password has exceeded its defined lifetime, the end
result is a password that is not changed per policy requirements.

    RHEL 8 utilizes "pwquality" consecutively as a mechanism to enforce
password complexity. This is set in both:
    /etc/pam.d/password-auth
    /etc/pam.d/system-auth.

    Note that manual changes to the listed files may be overwritten by the
"authselect" program.

```
New:
```
Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to reuse their password consecutively when that password has exceeded its defined lifetime, the end result is a password that is not changed per policy requirements.

RHEL 8 uses "pwhistory" consecutively as a mechanism to prohibit password reuse. This is set in both:
/etc/pam.d/password-auth
/etc/pam.d/system-auth.

Note that manual changes to the listed files may be overwritten by the "authselect" program.

```
---
SV-230369:
Old:
```
The shorter the password, the lower the number of possible
combinations that need to be tested before the password is compromised.

    Password complexity, or strength, is a measure of the effectiveness of a
password in resisting attempts at guessing and brute-force attacks. Password
length is one factor of several that helps to determine strength and how long
it takes to crack a password. Use of more characters in a password helps to
increase exponentially the time and/or resources required to compromise the
password.

    RHEL 8 utilizes "pwquality" as a mechanism to enforce password
complexity. Configurations are set in the "etc/security/pwquality.conf" file.

    The "minlen", sometimes noted as minimum length, acts as a "score" of
complexity based on the credit components of the "pwquality" module. By
setting the credit components to a negative value, not only will those
components be required, they will not count towards the total "score" of
"minlen". This will enable "minlen" to require a 15-character minimum.

    The DoD minimum password requirement is 15 characters.

```
New:
```
The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to increase exponentially the time and/or resources required to compromise the password.

RHEL 8 utilizes "pwquality" as a mechanism to enforce password complexity. Configurations are set in the "etc/security/pwquality.conf" file.

The "minlen", sometimes noted as minimum length, acts as a "score" of complexity based on the credit components of the "pwquality" module. By setting the credit components to a negative value, not only will those components be required, they will not count towards the total "score" of "minlen". This will enable "minlen" to require a 15-character minimum.

The DoD minimum password requirement is 15 characters.

```
---
SV-230370:
Old:
```
The shorter the password, the lower the number of possible
combinations that need to be tested before the password is compromised.

    Password complexity, or strength, is a measure of the effectiveness of a
password in resisting attempts at guessing and brute-force attacks. Password
length is one factor of several that helps to determine strength and how long
it takes to crack a password. Use of more characters in a password helps to
increase exponentially the time and/or resources required to compromise the
password.

    The DoD minimum password requirement is 15 characters.

```
New:
```
The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to increase exponentially the time and/or resources required to compromise the password.

The DoD minimum password requirement is 15 characters.

```
---
SV-230371:
Old:
```
To ensure accountability and prevent unauthenticated access,
interactive users must be identified and authenticated to prevent potential
misuse and compromise of the system.

    Interactive users include organizational employees or individuals the
organization deems to have equivalent status of employees (e.g., contractors).
Interactive users (and processes acting on behalf of users) must be uniquely
identified and authenticated to all accesses, except for the following:

    1) Accesses explicitly identified and documented by the organization.
Organizations document specific user actions that can be performed on the
information system without identification or authentication; and

    2) Accesses that occur through authorized use of group authenticators
without individual authentication. Organizations may require unique
identification of individuals in group accounts (e.g., shared privilege
accounts) or for detailed accountability of individual activity.

```
New:
```
To ensure accountability and prevent unauthenticated access, interactive users must be identified and authenticated to prevent potential misuse and compromise of the system.

Interactive users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Interactive users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following:

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.



```
---
SV-230372:
Old:
```
Using an authentication device, such as a Common Access Card (CAC) or
token that is separate from the information system, ensures that even if the
information system is compromised, that compromise will not affect credentials
stored on the authentication device.

    Multifactor solutions that require devices separate from information
systems gaining access include, for example, hardware tokens providing
time-based or challenge-response authenticators and smart cards such as the
U.S. Government Personal Identity Verification card and the DoD CAC.

    There are various methods of implementing multifactor authentication for
RHEL 8. Some methods include a local system multifactor account mapping or
joining the system to a domain and utilizing a Red Hat idM server or Microsoft
Windows Active Directory server. Any of these methods will require that the
client operating system handle the multifactor authentication correctly.

```
New:
```
Using an authentication device, such as a Common Access Card (CAC) or token that is separate from the information system, ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device.

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD CAC.

There are various methods of implementing multifactor authentication for RHEL 8. Some methods include a local system multifactor account mapping or joining the system to a domain and utilizing a Red Hat idM server or Microsoft Windows Active Directory server. Any of these methods will require that the client operating system handle the multifactor authentication correctly.



```
---
SV-230373:
Old:
```
Inactive identifiers pose a risk to systems and applications because
attackers may exploit an inactive identifier and potentially obtain undetected
access to the system. Owners of inactive accounts will not notice if
unauthorized access to their user account has been obtained.

    RHEL 8 needs to track periods of inactivity and disable application
identifiers after 35 days of inactivity.

```
New:
```
Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.

RHEL 8 needs to track periods of inactivity and disable application identifiers after 35 days of inactivity.

```
---
SV-230374:
Old:
```
Emergency accounts are privileged accounts established in response to
crisis situations where the need for rapid account activation is required.
Therefore, emergency account activation may bypass normal account authorization
processes. If these accounts are automatically disabled, system maintenance
during emergencies may not be possible, thus adversely affecting system
availability.

    Emergency accounts are different from infrequently used accounts (i.e.,
local logon accounts used by the organization's system administrators when
network or normal logon/access is not available). Infrequently used accounts
are not subject to automatic termination dates. Emergency accounts are accounts
created in response to crisis situations, usually for use by maintenance
personnel. The automatic expiration or disabling time period may be extended as
needed until the crisis is resolved; however, it must not be extended
indefinitely. A permanent account should be established for privileged users
who need long-term maintenance accounts.

    To address access requirements, many RHEL 8 systems can be integrated with
enterprise-level authentication/access mechanisms that meet or exceed access
control policy requirements.

```
New:
```
Temporary accounts are privileged or nonprivileged accounts that are established during pressing circumstances, such as new software or hardware configuration or an incident response, where the need for prompt account activation requires bypassing normal account authorization procedures. If any inactive temporary accounts are left enabled on the system and are not either manually removed or automatically expired within 72 hours, the security posture of the system will be degraded and exposed to exploitation by unauthorized users or insider threat actors.

Temporary accounts are different from emergency accounts. Emergency accounts, also known as "last resort" or "break glass" accounts, are local logon accounts enabled on the system for emergency use by authorized system administrators to manage a system when standard logon methods are failing or not available. Emergency accounts are not subject to manual removal or scheduled expiration requirements.

The automatic expiration of temporary accounts may be extended as needed by the circumstances but it must not be extended indefinitely. A documented permanent account should be established for privileged users who need long-term maintenance accounts.

```
---
SV-230375:
Old:
```
Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks.

    Password complexity is one factor of several that determines how long it
takes to crack a password. The more complex the password, the greater the
number of possible combinations that need to be tested before the password is
compromised.

    RHEL 8 utilizes "pwquality" as a mechanism to enforce password
complexity. Note that to require special characters without degrading the
"minlen" value, the credit value must be expressed as a negative number in
"/etc/security/pwquality.conf".

```
New:
```
Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

RHEL 8 utilizes "pwquality" as a mechanism to enforce password complexity. Note that to require special characters without degrading the "minlen" value, the credit value must be expressed as a negative number in "/etc/security/pwquality.conf".

```
---
SV-230376:
Old:
```
If cached authentication information is out-of-date, the validity of
the authentication information may be questionable.

    RHEL 8 includes multiple options for configuring authentication, but this
requirement will be focus on the System Security Services Daemon (SSSD). By
default sssd does not cache credentials.

```
New:
```
If cached authentication information is out-of-date, the validity of the authentication information may be questionable.

RHEL 8 includes multiple options for configuring authentication, but this requirement will be focus on the System Security Services Daemon (SSSD). By default sssd does not cache credentials.

```
---
SV-230377:
Old:
```
If RHEL 8 allows the user to select passwords based on dictionary
words, this increases the chances of password compromise by increasing the
opportunity for successful guesses, and brute-force attacks.

```
New:
```
If RHEL 8 allows the user to select passwords based on dictionary words, this increases the chances of password compromise by increasing the opportunity for successful guesses, and brute-force attacks.

```
---
SV-230378:
Old:
```
Configuring the operating system to implement organization-wide
security implementation guides and security checklists verifies compliance with
federal standards and establishes a common security baseline across the DoD
that reflects the most restrictive security posture consistent with operational
requirements.

    Configuration settings are the set of parameters that can be changed in
hardware, software, or firmware components of the system that affect the
security posture and/or functionality of the system. Security-related
parameters are those parameters impacting the security state of the system,
including the parameters required to satisfy other security control
requirements. Security-related parameters include, for example, registry
settings; account, file, and directory permission settings; and settings for
functions, ports, protocols, services, and remote connections.

```
New:
```
Configuring the operating system to implement organization-wide security implementation guides and security checklists verifies compliance with federal standards and establishes a common security baseline across the DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example, registry settings; account, file, and directory permission settings; and settings for functions, ports, protocols, services, and remote connections.

```
---
SV-230379:
Old:
```
Accounts providing no operational purpose provide additional
opportunities for system compromise. Unnecessary accounts include user accounts
for individuals not requiring access to the system and application accounts for
applications not installed on the system.

```
New:
```
Accounts providing no operational purpose provide additional opportunities for system compromise. Unnecessary accounts include user accounts for individuals not requiring access to the system and application accounts for applications not installed on the system.

```
---
SV-230380:
Old:
```
If an account has an empty password, anyone could log on and run
commands with the privileges of that account. Accounts with empty passwords
should never be used in operational environments.

```
New:
```
If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.

```
---
SV-230381:
Old:
```
Providing users with feedback on when account accesses last occurred
facilitates user recognition and reporting of unauthorized account use.

```
New:
```
Providing users with feedback on when account accesses last occurred facilitates user recognition and reporting of unauthorized account use.

```
---
SV-230382:
Old:
```
Providing users with feedback on when account accesses via SSH last
occurred facilitates user recognition and reporting of unauthorized account
use.

```
New:
```
Providing users with feedback on when account accesses via SSH last occurred facilitates user recognition and reporting of unauthorized account use.

```
---
SV-230383:
Old:
```
Setting the most restrictive default permissions ensures that when new
accounts are created, they do not have unnecessary access.

```
New:
```
Setting the most restrictive default permissions ensures that when new accounts are created, they do not have unnecessary access.

```
---
SV-230384:
Old:
```
The umask controls the default access mode assigned to newly created
files. A umask of 077 limits new files to mode 600 or less permissive. Although
umask can be represented as a four-digit number, the first digit representing
special access modes is typically ignored or required to be "0". This
requirement applies to the globally configured system defaults and the local
interactive user defaults for each account on the system.

```
New:
```
The umask controls the default access mode assigned to newly created files. A umask of 077 limits new files to mode 600 or less permissive. Although umask can be represented as a four-digit number, the first digit representing special access modes is typically ignored or required to be "0". This requirement applies to the globally configured system defaults and the local interactive user defaults for each account on the system.

```
---
SV-230385:
Old:
```
The umask controls the default access mode assigned to newly created
files. A umask of 077 limits new files to mode 600 or less permissive. Although
umask can be represented as a four-digit number, the first digit representing
special access modes is typically ignored or required to be "0". This
requirement applies to the globally configured system defaults and the local
interactive user defaults for each account on the system.

```
New:
```
The umask controls the default access mode assigned to newly created files. A umask of 077 limits new files to mode 600 or less permissive. Although umask can be represented as a four-digit number, the first digit representing special access modes is typically ignored or required to be "0". This requirement applies to the globally configured system defaults and the local interactive user defaults for each account on the system.

```
---
SV-230386:
Old:
```
Misuse of privileged functions, either intentionally or
unintentionally by authorized users, or by unauthorized external entities that
have compromised information system accounts, is a serious and ongoing concern
and can have significant adverse impacts on organizations. Auditing the use of
privileged functions is one way to detect such misuse and identify the risk
from insider threats and the advanced persistent threat.

```
New:
```
Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.



```
---
SV-230387:
Old:
```
Cron logging can be used to trace the successful or unsuccessful
execution of cron jobs. It can also be used to spot intrusions into the use of
the cron facility by unauthorized and malicious users.

```
New:
```
Cron logging can be used to trace the successful or unsuccessful execution of cron jobs. It can also be used to spot intrusions into the use of the cron facility by unauthorized and malicious users.

```
---
SV-230388:
Old:
```
It is critical for the appropriate personnel to be aware if a system
is at risk of failing to process audit logs as required. Without this
notification, the security personnel may be unaware of an impending failure of
the audit capability, and system operation may be adversely affected.

    Audit processing failures include software/hardware errors, failures in the
audit capturing mechanisms, and audit storage capacity being reached or
exceeded.

    This requirement applies to each audit data storage repository (i.e.,
distinct information system component where audit records are stored), the
centralized audit storage capacity of organizations (i.e., all audit data
storage repositories combined), or both.

```
New:
```
It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.

```
---
SV-230389:
Old:
```
It is critical for the appropriate personnel to be aware if a system
is at risk of failing to process audit logs as required. Without this
notification, the security personnel may be unaware of an impending failure of
the audit capability, and system operation may be adversely affected.

    Audit processing failures include software/hardware errors, failures in the
audit capturing mechanisms, and audit storage capacity being reached or
exceeded.

    This requirement applies to each audit data storage repository (i.e.,
distinct information system component where audit records are stored), the
centralized audit storage capacity of organizations (i.e., all audit data
storage repositories combined), or both.

```
New:
```
It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.

```
---
SV-230390:
Old:
```
It is critical for the appropriate personnel to be aware if a system
is at risk of failing to process audit logs as required. Without this
notification, the security personnel may be unaware of an impending failure of
the audit capability, and system operation may be adversely affected.

    Audit processing failures include software/hardware errors, failures in the
audit capturing mechanisms, and audit storage capacity being reached or
exceeded.

    This requirement applies to each audit data storage repository (i.e.,
distinct information system component where audit records are stored), the
centralized audit storage capacity of organizations (i.e., all audit data
storage repositories combined), or both.

```
New:
```
It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.

```
---
SV-230392:
Old:
```
It is critical that when RHEL 8 is at risk of failing to process audit
logs as required, it takes action to mitigate the failure. Audit processing
failures include software/hardware errors; failures in the audit capturing
mechanisms; and audit storage capacity being reached or exceeded. Responses to
audit failure depend upon the nature of the failure mode.

    When availability is an overriding concern, other approved actions in
response to an audit failure are as follows:

    1) If the failure was caused by the lack of audit record storage capacity,
RHEL 8 must continue generating audit records if possible (automatically
restarting the audit service if necessary) and overwriting the oldest audit
records in a first-in-first-out manner.

    2) If audit records are sent to a centralized collection server and
communication with this server is lost or the server fails, RHEL 8 must queue
audit records locally until communication is restored or until the audit
records are retrieved manually. Upon restoration of the connection to the
centralized collection server, action should be taken to synchronize the local
audit data with the collection server.

```
New:
```
It is critical that when RHEL 8 is at risk of failing to process audit logs as required, it takes action to mitigate the failure. Audit processing failures include software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode.

When availability is an overriding concern, other approved actions in response to an audit failure are as follows: 

1) If the failure was caused by the lack of audit record storage capacity, RHEL 8 must continue generating audit records if possible (automatically restarting the audit service if necessary) and overwriting the oldest audit records in a first-in-first-out manner.

2) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, RHEL 8 must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.

```
---
SV-230393:
Old:
```
Without establishing what type of events occurred, the source of
events, where events occurred, and the outcome of events, it would be difficult
to establish, correlate, and investigate the events leading up to an outage or
attack.

    Audit record content that may be necessary to satisfy this requirement
includes, for example, time stamps, source and destination addresses,
user/process identifiers, event descriptions, success/fail indications,
filenames involved, and access control or flow control rules invoked.

```
New:
```
Without establishing what type of events occurred, the source of events, where events occurred, and the outcome of events, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

```
---
SV-230394:
Old:
```
Without establishing what type of events occurred, the source of
events, where events occurred, and the outcome of events, it would be difficult
to establish, correlate, and investigate the events leading up to an outage or
attack.

    Audit record content that may be necessary to satisfy this requirement
includes, for example, time stamps, source and destination addresses,
user/process identifiers, event descriptions, success/fail indications,
filenames involved, and access control or flow control rules invoked.

    Enriched logging is needed to determine who, what, and when events occur on
a system.  Without this, determining root cause of an event will be much more
difficult.

    When audit logs are not labeled before they are sent to a central log
server, the audit data will not be able to be analyzed and tied back to the
correct system.

```
New:
```
Without establishing what type of events occurred, the source of events, where events occurred, and the outcome of events, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Enriched logging is needed to determine who, what, and when events occur on a system.  Without this, determining root cause of an event will be much more difficult.

When audit logs are not labeled before they are sent to a central log server, the audit data will not be able to be analyzed and tied back to the correct system.

```
---
SV-230395:
Old:
```
Without establishing what type of events occurred, the source of
events, where events occurred, and the outcome of events, it would be difficult
to establish, correlate, and investigate the events leading up to an outage or
attack.

    Audit record content that may be necessary to satisfy this requirement
includes, for example, time stamps, source and destination addresses,
user/process identifiers, event descriptions, success/fail indications,
filenames involved, and access control or flow control rules invoked.

    Enriched logging aids in making sense of who, what, and when events occur
on a system.  Without this, determining root cause of an event will be much
more difficult.

```
New:
```
Without establishing what type of events occurred, the source of events, where events occurred, and the outcome of events, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Enriched logging aids in making sense of who, what, and when events occur on a system.  Without this, determining root cause of an event will be much more difficult.

```
---
SV-230396:
Old:
```
Only authorized personnel should be aware of errors and the details of
the errors. Error messages are an indicator of an organization's operational
state or can identify the RHEL 8 system or platform. Additionally, Personally
Identifiable Information (PII) and operational information must not be revealed
through error messages to unauthorized personnel or their designated
representatives.

    The structure and content of error messages must be carefully considered by
the organization and development team. The extent to which the information
system is able to identify and handle error conditions is guided by
organizational policy and operational requirements.

```
New:
```
Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the RHEL 8 system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.



```
---
SV-230397:
Old:
```
Only authorized personnel should be aware of errors and the details of
the errors. Error messages are an indicator of an organization's operational
state or can identify the RHEL 8 system or platform. Additionally, Personally
Identifiable Information (PII) and operational information must not be revealed
through error messages to unauthorized personnel or their designated
representatives.

    The structure and content of error messages must be carefully considered by
the organization and development team. The extent to which the information
system is able to identify and handle error conditions is guided by
organizational policy and operational requirements.

```
New:
```
Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the RHEL 8 system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.



```
---
SV-230398:
Old:
```
Unauthorized disclosure of audit records can reveal system and
configuration data to attackers, thus compromising its confidentiality.

    Audit information includes all information (e.g., audit records, audit
settings, audit reports) needed to successfully audit RHEL 8 activity.

```
New:
```
Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit RHEL 8 activity.



```
---
SV-230399:
Old:
```
Unauthorized disclosure of audit records can reveal system and
configuration data to attackers, thus compromising its confidentiality.

    Audit information includes all information (e.g., audit records, audit
settings, audit reports) needed to successfully audit RHEL 8 activity.

```
New:
```
Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit RHEL 8 activity.



```
---
SV-230400:
Old:
```
Unauthorized disclosure of audit records can reveal system and
configuration data to attackers, thus compromising its confidentiality.

    Audit information includes all information (e.g., audit records, audit
settings, audit reports) needed to successfully audit RHEL 8 activity.

```
New:
```
Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit RHEL 8 activity.



```
---
SV-230401:
Old:
```
Unauthorized disclosure of audit records can reveal system and
configuration data to attackers, thus compromising its confidentiality.

    Audit information includes all information (e.g., audit records, audit
settings, audit reports) needed to successfully audit RHEL 8 system activity.

```
New:
```
Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit RHEL 8 system activity.



```
---
SV-230402:
Old:
```
Unauthorized disclosure of audit records can reveal system and
configuration data to attackers, thus compromising its confidentiality.

    Audit information includes all information (e.g., audit records, audit
settings, audit reports) needed to successfully audit RHEL 8 system activity.

    In immutable mode, unauthorized users cannot execute changes to the audit
system to potentially hide malicious activity and then put the audit rules
back.  A system reboot would be noticeable and a system administrator could
then investigate the unauthorized changes.

```
New:
```
Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit RHEL 8 system activity.

In immutable mode, unauthorized users cannot execute changes to the audit system to potentially hide malicious activity and then put the audit rules back.  A system reboot would be noticeable and a system administrator could then investigate the unauthorized changes.



```
---
SV-230403:
Old:
```
Unauthorized disclosure of audit records can reveal system and
configuration data to attackers, thus compromising its confidentiality.

    Audit information includes all information (e.g., audit records, audit
settings, audit reports) needed to successfully audit RHEL 8 system activity.

    In immutable mode, unauthorized users cannot execute changes to the audit
system to potentially hide malicious activity and then put the audit rules
back.  A system reboot would be noticeable and a system administrator could
then investigate the unauthorized changes.

```
New:
```
Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit RHEL 8 system activity.

In immutable mode, unauthorized users cannot execute changes to the audit system to potentially hide malicious activity and then put the audit rules back.  A system reboot would be noticeable and a system administrator could then investigate the unauthorized changes.



```
---
SV-230404:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).



```
---
SV-230405:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).



```
---
SV-230406:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).



```
---
SV-230407:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).



```
---
SV-230408:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).



```
---
SV-230409:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).



```
---
SV-230410:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).



```
---
SV-230411:
Old:
```
Without establishing what type of events occurred, the source of
events, where events occurred, and the outcome of events, it would be difficult
to establish, correlate, and investigate the events leading up to an outage or
attack.

    Audit record content that may be necessary to satisfy this requirement
includes, for example, time stamps, source and destination addresses,
user/process identifiers, event descriptions, success/fail indications,
filenames involved, and access control or flow control rules invoked.

    Associating event types with detected events in RHEL 8 audit logs provides
a means of investigating an attack, recognizing resource utilization or
capacity thresholds, or identifying an improperly configured RHEL 8 system.

```
New:
```
Without establishing what type of events occurred, the source of events, where events occurred, and the outcome of events, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in RHEL 8 audit logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured RHEL 8 system.



```
---
SV-230412:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "su" command allows a
user to run commands with a substitute user and group ID.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "su" command allows a user to run commands with a substitute user and group ID.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230413:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). "Lremovexattr" is a
system call that removes extended attributes. This is used for removal of
extended attributes from symbolic links.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). 

"Setxattr" is a system call used to set an extended attribute value.
"Fsetxattr" is a system call used to set an extended attribute value. This is used to set extended attributes on a file.
"Lsetxattr" is a system call used to set an extended attribute value. This is used to set extended attributes on a symbolic link.
"Removexattr" is a system call that removes extended attributes.
"Fremovexattr" is a system call that removes extended attributes. This is used for removal of extended attributes from a file.
"Lremovexattr" is a system call that removes extended attributes. This is used for removal of extended attributes from symbolic links.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.

The system call rules are loaded into a matching engine that intercepts each syscall made by all programs on the system. Therefore, it is very important to use syscall rules only when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance can be helped, however, by combining syscalls into one rule whenever possible.



```
---
SV-230418:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "chage" command is
used to change or view user password expiry information.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "chage" command is used to change or view user password expiry information.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230419:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "chcon" command is
used to change file SELinux security context.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "chcon" command is used to change file SELinux security context.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230421:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "ssh-agent" is a
program to hold private keys used for public key authentication.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "ssh-agent" is a program to hold private keys used for public key authentication.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230422:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "passwd" command is
used to change passwords for user accounts.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "passwd" command is used to change passwords for user accounts.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230423:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "mount" command is
used to mount a filesystem.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "mount" command is used to mount a filesystem.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230424:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "umount" command is
used to unmount a filesystem.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "umount" command is used to unmount a filesystem.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230425:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "mount" syscall is
used to mount a filesystem.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "mount" syscall is used to mount a filesystem.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230426:
Old:
```
Reconstruction of harmful events or forensic analysis is not possible
if audit records do not contain enough information.

    At a minimum, the organization must audit the full-text recording of
privileged commands. The organization must maintain audit trails in sufficient
detail to reconstruct events to determine the cause and impact of compromise.
"Unix_update" is a helper program for the "pam_unix" module that updates
the password for a given user. It is not intended to be run directly from the
command line and logs a security violation if done so.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. "Unix_update" is a helper program for the "pam_unix" module that updates the password for a given user. It is not intended to be run directly from the command line and logs a security violation if done so.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230427:
Old:
```
Reconstruction of harmful events or forensic analysis is not possible
if audit records do not contain enough information.

    At a minimum, the organization must audit the full-text recording of
privileged commands. The organization must maintain audit trails in sufficient
detail to reconstruct events to determine the cause and impact of compromise.
The "postdrop" command creates a file in the maildrop directory and copies
its standard input to the file.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. The "postdrop" command creates a file in the maildrop directory and copies its standard input to the file.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230428:
Old:
```
Reconstruction of harmful events or forensic analysis is not possible
if audit records do not contain enough information.

    At a minimum, the organization must audit the full-text recording of
privileged commands. The organization must maintain audit trails in sufficient
detail to reconstruct events to determine the cause and impact of compromise.
The "postqueue" command implements the Postfix user interface for queue
management.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. The "postqueue" command implements the Postfix user interface for queue management.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230429:
Old:
```
Reconstruction of harmful events or forensic analysis is not possible
if audit records do not contain enough information.

    At a minimum, the organization must audit the full-text recording of
privileged commands. The organization must maintain audit trails in sufficient
detail to reconstruct events to determine the cause and impact of compromise.
The "semanage" command is used to configure certain elements of SELinux
policy without requiring modification to or recompilation from policy sources.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. The "semanage" command is used to configure certain elements of SELinux policy without requiring modification to or recompilation from policy sources.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230430:
Old:
```
Reconstruction of harmful events or forensic analysis is not possible
if audit records do not contain enough information.

    At a minimum, the organization must audit the full-text recording of
privileged commands. The organization must maintain audit trails in sufficient
detail to reconstruct events to determine the cause and impact of compromise.
The "setfiles" command is primarily used to initialize the security context
fields (extended attributes) on one or more filesystems (or parts of them).
Usually it is initially run as part of the SELinux installation process (a step
commonly known as labeling).

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. The "setfiles" command is primarily used to initialize the security context fields (extended attributes) on one or more filesystems (or parts of them).  Usually it is initially run as part of the SELinux installation process (a step commonly known as labeling).

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230431:
Old:
```
Reconstruction of harmful events or forensic analysis is not possible
if audit records do not contain enough information.

    At a minimum, the organization must audit the full-text recording of
privileged commands. The organization must maintain audit trails in sufficient
detail to reconstruct events to determine the cause and impact of compromise.
The "userhelper" command is not intended to be run interactively.
"Userhelper" provides a basic interface to change a user's password, gecos
information, and shell.  The main difference between this program and its
traditional equivalents (passwd, chfn, chsh) is that prompts are written to
standard out to make it easy for a graphical user interface wrapper to
interface to it as a child process.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. The "userhelper" command is not intended to be run interactively.  "Userhelper" provides a basic interface to change a user's password, gecos information, and shell.  The main difference between this program and its traditional equivalents (passwd, chfn, chsh) is that prompts are written to standard out to make it easy for a graphical user interface wrapper to interface to it as a child process.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230432:
Old:
```
Reconstruction of harmful events or forensic analysis is not possible
if audit records do not contain enough information.

    At a minimum, the organization must audit the full-text recording of
privileged commands. The organization must maintain audit trails in sufficient
detail to reconstruct events to determine the cause and impact of compromise.
The "setsebool" command sets the current state of a particular SELinux
boolean or a list of booleans to a given value.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. The "setsebool" command sets the current state of a particular SELinux boolean or a list of booleans to a given value.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230433:
Old:
```
Reconstruction of harmful events or forensic analysis is not possible
if audit records do not contain enough information.

    At a minimum, the organization must audit the full-text recording of
privileged commands. The organization must maintain audit trails in sufficient
detail to reconstruct events to determine the cause and impact of compromise.
The "unix_chkpwd" command is a helper program for the pam_unix module that
verifies the password of the current user.  It also checks password and account
expiration dates in shadow.  It is not intended to be run directly from the
command line and logs a security violation if done so.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. The "unix_chkpwd" command is a helper program for the pam_unix module that verifies the password of the current user.  It also checks password and account expiration dates in shadow.  It is not intended to be run directly from the command line and logs a security violation if done so.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230434:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "ssh-keysign" program
is an SSH helper program for host-based authentication.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "ssh-keysign" program is an SSH helper program for host-based authentication.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230435:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "setfacl" command is
used to set file access control lists.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "setfacl" command is used to set file access control lists.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230436:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "pam_timestamp_check"
command is used to check if the default timestamp is valid.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "pam_timestamp_check" command is used to check if the default timestamp is valid.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230437:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "newgrp" command is
used to change the current group ID during a login session.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "newgrp" command is used to change the current group ID during a login session.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230438:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "init_module" command
is used to load a kernel module.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "init_module" and "finit_module" system calls are used to load a kernel module.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.

The system call rules are loaded into a matching engine that intercepts each syscall made by all programs on the system. Therefore, it is very important to use syscall rules only when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance can be helped, however, by combining syscalls into one rule whenever possible.



```
---
SV-230439:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "rename" command will
rename the specified files by replacing the first occurrence of expression in
their name by replacement.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "rename" system call will rename the specified files by replacing the first occurrence of expression in their name by replacement.

The "unlink" system call deletes a name from the filesystem. If that name was the last link to a file and no processes have the file open, the file is deleted and the space it was using is made available for reuse.
The "rmdir" system call removes empty directories.
The "renameat" system call renames a file, moving it between directories if required.
The "unlinkat" system call operates in exactly the same way as either "unlink" or "rmdir" except for the differences described in the manual page.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.

The system call rules are loaded into a matching engine that intercepts each syscall made by all programs on the system. Therefore, it is very important to use syscall rules only when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. Performance can be helped, however, by combining syscalls into one rule whenever possible.



```
---
SV-230444:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "gpasswd" command is
used to administer /etc/group and /etc/gshadow. Every group can have
administrators, members and a password.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "gpasswd" command is used to administer /etc/group and /etc/gshadow. Every group can have administrators, members and a password.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230446:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "delete_module"
command is used to unload a kernel module.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "delete_module" command is used to unload a kernel module.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230447:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "crontab" command is
used to maintain crontab files for individual users. Crontab is the program
used to install, remove, or list the tables used to drive the cron daemon. This
is similar to the task scheduler used in other operating systems.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "crontab" command is used to maintain crontab files for individual users. Crontab is the program used to install, remove, or list the tables used to drive the cron daemon. This is similar to the task scheduler used in other operating systems.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230448:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "chsh" command is
used to change the login shell.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "chsh" command is used to change the login shell.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230449:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "truncate" and
"ftruncate" functions are used to truncate a file to a specified length.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "truncate" and "ftruncate" functions are used to truncate a file to a specified length. 

The "creat" system call is used to open and possibly create a file or device.
The "open" system call opens a file specified by a pathname. If the specified file does not exist, it may optionally be created by "open".
The "openat" system call opens a file specified by a relative pathname.
The "name_to_handle_at" and "open_by_handle_at" system calls split the functionality of "openat" into two parts: "name_to_handle_at" returns an opaque handle that corresponds to a specified file; "open_by_handle_at" opens the file corresponding to a handle returned by a previous call to "name_to_handle_at" and returns an open file descriptor.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.

The system call rules are loaded into a matching engine that intercepts each syscall made by all programs on the system. Therefore, it is very important to use syscall rules only when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance can be helped, however, by combining syscalls into one rule whenever possible.



```
---
SV-230455:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "chown" command is
used to change file owner and group.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "chown" command is used to change file owner and group.

The "fchown" system call is used to change the ownership of a file referred to by the open file descriptor.
The "fchownat" system call is used to change ownership of a file relative to a directory file descriptor.
The "lchown" system call is used to change the ownership of the file specified by a path, which does not dereference symbolic links.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.

The system call rules are loaded into a matching engine that intercepts each syscall made by all programs on the system. Therefore, it is very important to use syscall rules only when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance can be helped, however, by combining syscalls into one rule whenever possible.



```
---
SV-230456:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "chmod" command
changes the file mode bits of each given file according to mode, which can be
either a symbolic representation of changes to make, or an octal number
representing the bit pattern for the new mode bits.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "chmod" system call changes the file mode bits of each given file according to mode, which can be either a symbolic representation of changes to make, or an octal number representing the bit pattern for the new mode bits.

The "fchmod" system call is used to change permissions of a file.
The "fchmodat" system call is used to change permissions of a file relative to a directory file descriptor.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.

The system call rules are loaded into a matching engine that intercepts each syscall made by all programs on the system. Therefore, it is very important to use syscall rules only when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. Performance can be helped, however, by combining syscalls into one rule whenever possible.



```
---
SV-230462:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "sudo" command allows
a permitted user to execute a command as the superuser or another user, as
specified by the security policy.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "sudo" command allows a permitted user to execute a command as the superuser or another user, as specified by the security policy.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230463:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "usermod" command
modifies the system account files to reflect the changes that are specified on
the command line.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "usermod" command modifies the system account files to reflect the changes that are specified on the command line.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230464:
Old:
```
Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "chacl" command is
used to change the access control list of a file or directory.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "chacl" command is used to change the access control list of a file or directory.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.



```
---
SV-230465:
Old:
```
Without the capability to generate audit records, it would be
difficult to establish, correlate, and investigate the events relating to an
incident or identify those responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "kmod" command is
used to control Linux Kernel modules.

    The list of audited events is the set of events for which audits are to be
generated. This set of events is typically a subset of the list of all events
for which the system is capable of generating audit records.

    DoD has defined the list of events for which RHEL 8 will provide an audit
record generation capability as the following:

    1) Successful and unsuccessful attempts to access, modify, or delete
privileges, security objects, security levels, or categories of information
(e.g., classification levels);

    2) Access actions, such as successful and unsuccessful logon attempts,
privileged activities or other system-level access, starting and ending time
for user access to the system, concurrent logons from different workstations,
successful and unsuccessful accesses to objects, all program initiations, and
all direct access to the information system;

    3) All account creations, modifications, disabling, and terminations; and

    4) All kernel module load, unload, and restart actions.

```
New:
```
Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "kmod" command is used to control Linux Kernel modules.

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which RHEL 8 will provide an audit record generation capability as the following:

1) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

2) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system;

3) All account creations, modifications, disabling, and terminations; and 

4) All kernel module load, unload, and restart actions.



```
---
SV-230466:
Old:
```
Without the capability to generate audit records, it would be
difficult to establish, correlate, and investigate the events relating to an
incident or identify those responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).

    The list of audited events is the set of events for which audits are to be
generated. This set of events is typically a subset of the list of all events
for which the system is capable of generating audit records.

    DoD has defined the list of events for which RHEL 8 will provide an audit
record generation capability as the following:

    1) Successful and unsuccessful attempts to access, modify, or delete
privileges, security objects, security levels, or categories of information
(e.g., classification levels);

    2) Access actions, such as successful and unsuccessful logon attempts,
privileged activities or other system-level access, starting and ending time
for user access to the system, concurrent logons from different workstations,
successful and unsuccessful accesses to objects, all program initiations, and
all direct access to the information system;

    3) All account creations, modifications, disabling, and terminations; and

    4) All kernel module load, unload, and restart actions.

    From "Pam_Faillock man" pages: Note the default directory that
pam_faillock uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the "dir" option.

```
New:
```
Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which RHEL 8 will provide an audit record generation capability as the following:

1) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

2) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system;

3) All account creations, modifications, disabling, and terminations; and

4) All kernel module load, unload, and restart actions.

From "Pam_Faillock man" pages: Note the default directory that pam_faillock uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable a different tally directory must be set with the "dir" option.



```
---
SV-230467:
Old:
```
Without the capability to generate audit records, it would be
difficult to establish, correlate, and investigate the events relating to an
incident or identify those responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).

    The list of audited events is the set of events for which audits are to be
generated. This set of events is typically a subset of the list of all events
for which the system is capable of generating audit records.

    DoD has defined the list of events for which RHEL 8 will provide an audit
record generation capability as the following:

    1) Successful and unsuccessful attempts to access, modify, or delete
privileges, security objects, security levels, or categories of information
(e.g., classification levels);

    2) Access actions, such as successful and unsuccessful logon attempts,
privileged activities or other system-level access, starting and ending time
for user access to the system, concurrent logons from different workstations,
successful and unsuccessful accesses to objects, all program initiations, and
all direct access to the information system;

    3) All account creations, modifications, disabling, and terminations; and

    4) All kernel module load, unload, and restart actions.

```
New:
```
Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which RHEL 8 will provide an audit record generation capability as the following:

1) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

2) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system;

3) All account creations, modifications, disabling, and terminations; and 

4) All kernel module load, unload, and restart actions.



```
---
SV-230468:
Old:
```
Without the capability to generate audit records, it would be
difficult to establish, correlate, and investigate the events relating to an
incident or identify those responsible for one.

    If auditing is enabled late in the startup process, the actions of some
startup processes may not be audited. Some audit systems also maintain state
information only available if auditing is enabled before a given process is
created.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).

    The list of audited events is the set of events for which audits are to be
generated. This set of events is typically a subset of the list of all events
for which the system is capable of generating audit records.

    DoD has defined the list of events for which RHEL 8 will provide an audit
record generation capability as the following:

    1) Successful and unsuccessful attempts to access, modify, or delete
privileges, security objects, security levels, or categories of information
(e.g., classification levels);

    2) Access actions, such as successful and unsuccessful logon attempts,
privileged activities or other system-level access, starting and ending time
for user access to the system, concurrent logons from different workstations,
successful and unsuccessful accesses to objects, all program initiations, and
all direct access to the information system;

    3) All account creations, modifications, disabling, and terminations; and

    4) All kernel module load, unload, and restart actions.

```
New:
```
Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

If auditing is enabled late in the startup process, the actions of some startup processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which RHEL 8 will provide an audit record generation capability as the following:

1) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

2) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system;

3) All account creations, modifications, disabling, and terminations; and 

4) All kernel module load, unload, and restart actions.



```
---
SV-230469:
Old:
```
Without the capability to generate audit records, it would be
difficult to establish, correlate, and investigate the events relating to an
incident or identify those responsible for one.

    If auditing is enabled late in the startup process, the actions of some
startup processes may not be audited. Some audit systems also maintain state
information only available if auditing is enabled before a given process is
created.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).

    Allocating an audit_backlog_limit of sufficient size is critical in
maintaining a stable boot process.  With an insufficient limit allocated, the
system is susceptible to boot failures and crashes.

```
New:
```
Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

If auditing is enabled late in the startup process, the actions of some startup processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

Allocating an audit_backlog_limit of sufficient size is critical in maintaining a stable boot process.  With an insufficient limit allocated, the system is susceptible to boot failures and crashes.

```
---
SV-230470:
Old:
```
Without the capability to generate audit records, it would be
difficult to establish, correlate, and investigate the events relating to an
incident or identify those responsible for one.

    If auditing is enabled late in the startup process, the actions of some
startup processes may not be audited. Some audit systems also maintain state
information only available if auditing is enabled before a given process is
created.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).

    The list of audited events is the set of events for which audits are to be
generated. This set of events is typically a subset of the list of all events
for which the system is capable of generating audit records.

    DoD has defined the list of events for which RHEL 8 will provide an audit
record generation capability as the following:

    1) Successful and unsuccessful attempts to access, modify, or delete
privileges, security objects, security levels, or categories of information
(e.g., classification levels);

    2) Access actions, such as successful and unsuccessful logon attempts,
privileged activities or other system-level access, starting and ending time
for user access to the system, concurrent logons from different workstations,
successful and unsuccessful accesses to objects, all program initiations, and
all direct access to the information system;

    3) All account creations, modifications, disabling, and terminations; and

    4) All kernel module load, unload, and restart actions.

```
New:
```
Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

If auditing is enabled late in the startup process, the actions of some startup processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which RHEL 8 will provide an audit record generation capability as the following:

1) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

2) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system;

3) All account creations, modifications, disabling, and terminations; and 

4) All kernel module load, unload, and restart actions.



```
---
SV-230471:
Old:
```
Without the capability to restrict the roles and individuals that can
select which events are audited, unauthorized personnel may be able to prevent
the auditing of critical events. Misconfigured audits may degrade the system's
performance by overwhelming the audit log. Misconfigured audits may also make
it more difficult to establish, correlate, and investigate the events relating
to an incident or identify those responsible for one.

```
New:
```
Without the capability to restrict the roles and individuals that can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

```
---
SV-230472:
Old:
```
Protecting audit information also includes identifying and protecting
the tools used to view and manipulate log data. Therefore, protecting audit
tools is necessary to prevent unauthorized operation on audit information.

    RHEL 8 systems providing tools to interface with audit information will
leverage user permissions and roles identifying the user accessing the tools,
and the corresponding rights the user enjoys, to make access decisions
regarding the access to audit tools.

    Audit tools include, but are not limited to, vendor-provided and open
source audit tools needed to successfully view and manipulate audit information
system activity and records. Audit tools include custom queries and report
generators.

```
New:
```
Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

RHEL 8 systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools, and the corresponding rights the user enjoys, to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

```
---
SV-230473:
Old:
```
Protecting audit information also includes identifying and protecting
the tools used to view and manipulate log data. Therefore, protecting audit
tools is necessary to prevent unauthorized operation on audit information.

    RHEL 8 systems providing tools to interface with audit information will
leverage user permissions and roles identifying the user accessing the tools,
and the corresponding rights the user enjoys, to make access decisions
regarding the access to audit tools.

    Audit tools include, but are not limited to, vendor-provided and open
source audit tools needed to successfully view and manipulate audit information
system activity and records. Audit tools include custom queries and report
generators.

```
New:
```
Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

RHEL 8 systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools, and the corresponding rights the user enjoys, to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.



```
---
SV-230474:
Old:
```
Protecting audit information also includes identifying and protecting
the tools used to view and manipulate log data. Therefore, protecting audit
tools is necessary to prevent unauthorized operation on audit information.

    RHEL 8 systems providing tools to interface with audit information will
leverage user permissions and roles identifying the user accessing the tools,
and the corresponding rights the user enjoys, to make access decisions
regarding the access to audit tools.

    Audit tools include, but are not limited to, vendor-provided and open
source audit tools needed to successfully view and manipulate audit information
system activity and records. Audit tools include custom queries and report
generators.

```
New:
```
Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

RHEL 8 systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools, and the corresponding rights the user enjoys, to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.



```
---
SV-230475:
Old:
```
Protecting the integrity of the tools used for auditing purposes is a
critical step toward ensuring the integrity of audit information. Audit
information includes all information (e.g., audit records, audit settings, and
audit reports) needed to successfully audit information system activity.

    Audit tools include, but are not limited to, vendor-provided and open
source audit tools needed to successfully view and manipulate audit information
system activity and records. Audit tools include custom queries and report
generators.

    It is not uncommon for attackers to replace the audit tools or inject code
into the existing tools with the purpose of providing the capability to hide or
erase system activity from the audit logs.

    To address this risk, audit tools must be cryptographically signed to
provide the capability to identify when the audit tools have been modified,
manipulated, or replaced. An example is a checksum hash of the file or files.

```
New:
```
Protecting the integrity of the tools used for auditing purposes is a critical step toward ensuring the integrity of audit information. Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

It is not uncommon for attackers to replace the audit tools or inject code into the existing tools with the purpose of providing the capability to hide or erase system activity from the audit logs.

To address this risk, audit tools must be cryptographically signed to provide the capability to identify when the audit tools have been modified, manipulated, or replaced. An example is a checksum hash of the file or files.

```
---
SV-230476:
Old:
```
To ensure RHEL 8 systems have a sufficient storage capacity in which
to write the audit logs, RHEL 8 needs to be able to allocate audit record
storage capacity.

    The task of allocating audit record storage capacity is usually performed
during initial installation of RHEL 8.

```
New:
```
To ensure RHEL 8 systems have a sufficient storage capacity in which to write the audit logs, RHEL 8 needs to be able to allocate audit record storage capacity.

The task of allocating audit record storage capacity is usually performed during initial installation of RHEL 8.

```
---
SV-230477:
Old:
```
Information stored in one location is vulnerable to accidental or
incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit
storage capacity.

    RHEL 8 installation media provides "rsyslogd".  "rsyslogd" is a system
utility providing support for message logging.  Support for both internet and
UNIX domain sockets enables this utility to support both local and remote
logging.  Couple this utility with "gnutls" (which is a secure communications
library implementing the SSL, TLS and DTLS protocols), and you have a method to
securely encrypt and off-load auditing.

    Rsyslog provides three ways to forward message: the traditional UDP
transport, which is extremely lossy but standard; the plain TCP based
transport, which loses messages only during certain situations but is widely
available; and the RELP transport, which does not lose messages but is
currently available only as part of the rsyslogd 3.15.0 and above.
    Examples of each configuration:
    UDP *.* @remotesystemname
    TCP *.* @@remotesystemname
    RELP *.* :omrelp:remotesystemname:2514
    Note that a port number was given as there is no standard port for RELP.

```
New:
```
Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

RHEL 8 installation media provides "rsyslogd".  "rsyslogd" is a system utility providing support for message logging.  Support for both internet and UNIX domain sockets enables this utility to support both local and remote logging.  Couple this utility with "gnutls" (which is a secure communications library implementing the SSL, TLS and DTLS protocols), and you have a method to securely encrypt and off-load auditing.

Rsyslog provides three ways to forward message: the traditional UDP transport, which is extremely lossy but standard; the plain TCP based transport, which loses messages only during certain situations but is widely available; and the RELP transport, which does not lose messages but is currently available only as part of the rsyslogd 3.15.0 and above.
Examples of each configuration:
UDP *.* @remotesystemname
TCP *.* @@remotesystemname
RELP *.* :omrelp:remotesystemname:2514
Note that a port number was given as there is no standard port for RELP.

```
---
SV-230478:
Old:
```
Information stored in one location is vulnerable to accidental or
incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit
storage capacity.

    RHEL 8 installation media provides "rsyslogd".  "rsyslogd" is a system
utility providing support for message logging.  Support for both internet and
UNIX domain sockets enables this utility to support both local and remote
logging.  Couple this utility with "rsyslog-gnutls" (which is a secure
communications library implementing the SSL, TLS and DTLS protocols), and you
have a method to securely encrypt and off-load auditing.

    Rsyslog provides three ways to forward message: the traditional UDP
transport, which is extremely lossy but standard; the plain TCP based
transport, which loses messages only during certain situations but is widely
available; and the RELP transport, which does not lose messages but is
currently available only as part of the rsyslogd 3.15.0 and above.
    Examples of each configuration:
    UDP *.* @remotesystemname
    TCP *.* @@remotesystemname
    RELP *.* :omrelp:remotesystemname:2514
    Note that a port number was given as there is no standard port for RELP.

```
New:
```
Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

RHEL 8 installation media provides "rsyslogd".  "rsyslogd" is a system utility providing support for message logging.  Support for both internet and UNIX domain sockets enables this utility to support both local and remote logging.  Couple this utility with "rsyslog-gnutls" (which is a secure communications library implementing the SSL, TLS and DTLS protocols), and you have a method to securely encrypt and off-load auditing.

Rsyslog provides three ways to forward message: the traditional UDP transport, which is extremely lossy but standard; the plain TCP based transport, which loses messages only during certain situations but is widely available; and the RELP transport, which does not lose messages but is currently available only as part of the rsyslogd 3.15.0 and above.
Examples of each configuration:
UDP *.* @remotesystemname
TCP *.* @@remotesystemname
RELP *.* :omrelp:remotesystemname:2514
Note that a port number was given as there is no standard port for RELP.

```
---
SV-230479:
Old:
```
Information stored in one location is vulnerable to accidental or
incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit
storage capacity.

    RHEL 8 installation media provides "rsyslogd".  "rsyslogd" is a system
utility providing support for message logging.  Support for both internet and
UNIX domain sockets enables this utility to support both local and remote
logging.  Couple this utility with "gnutls" (which is a secure communications
library implementing the SSL, TLS and DTLS protocols), and you have a method to
securely encrypt and off-load auditing.

    Rsyslog provides three ways to forward message: the traditional UDP
transport, which is extremely lossy but standard; the plain TCP based
transport, which loses messages only during certain situations but is widely
available; and the RELP transport, which does not lose messages but is
currently available only as part of the rsyslogd 3.15.0 and above.
    Examples of each configuration:
    UDP *.* @remotesystemname
    TCP *.* @@remotesystemname
    RELP *.* :omrelp:remotesystemname:2514
    Note that a port number was given as there is no standard port for RELP.

```
New:
```
Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

RHEL 8 installation media provides "rsyslogd".  "rsyslogd" is a system utility providing support for message logging.  Support for both internet and UNIX domain sockets enables this utility to support both local and remote logging.  Couple this utility with "gnutls" (which is a secure communications library implementing the SSL, TLS and DTLS protocols), and you have a method to securely encrypt and off-load auditing.

Rsyslog provides three ways to forward message: the traditional UDP transport, which is extremely lossy but standard; the plain TCP based transport, which loses messages only during certain situations but is widely available; and the RELP transport, which does not lose messages but is currently available only as part of the rsyslogd 3.15.0 and above.
Examples of each configuration:
UDP *.* @remotesystemname
TCP *.* @@remotesystemname
RELP *.* :omrelp:remotesystemname:2514
Note that a port number was given as there is no standard port for RELP.



```
---
SV-230480:
Old:
```
Information stored in one location is vulnerable to accidental or
incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit
storage capacity.

    RHEL 8 installation media provides "rsyslogd".  "rsyslogd" is a system
utility providing support for message logging.  Support for both internet and
UNIX domain sockets enables this utility to support both local and remote
logging.  Couple this utility with "gnutls" (which is a secure communications
library implementing the SSL, TLS and DTLS protocols), and you have a method to
securely encrypt and off-load auditing.

```
New:
```
Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

RHEL 8 installation media provides "rsyslogd".  "rsyslogd" is a system utility providing support for message logging.  Support for both internet and UNIX domain sockets enables this utility to support both local and remote logging.  Couple this utility with "gnutls" (which is a secure communications library implementing the SSL, TLS and DTLS protocols), and you have a method to securely encrypt and off-load auditing.



```
---
SV-230481:
Old:
```
Information stored in one location is vulnerable to accidental or
incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit
storage capacity.

    RHEL 8 installation media provides "rsyslogd".  "rsyslogd" is a system
utility providing support for message logging.  Support for both internet and
UNIX domain sockets enables this utility to support both local and remote
logging.  Couple this utility with "gnutls" (which is a secure communications
library implementing the SSL, TLS and DTLS protocols), and you have a method to
securely encrypt and off-load auditing.

```
New:
```
Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

RHEL 8 installation media provides "rsyslogd".  "rsyslogd" is a system utility providing support for message logging.  Support for both internet and UNIX domain sockets enables this utility to support both local and remote logging.  Couple this utility with "gnutls" (which is a secure communications library implementing the SSL, TLS and DTLS protocols), and you have a method to securely encrypt and off-load auditing.



```
---
SV-230482:
Old:
```
Information stored in one location is vulnerable to accidental or
incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit
storage capacity.

    RHEL 8 installation media provides "rsyslogd".  "rsyslogd" is a system
utility providing support for message logging.  Support for both internet and
UNIX domain sockets enables this utility to support both local and remote
logging.  Couple this utility with "gnutls" (which is a secure communications
library implementing the SSL, TLS and DTLS protocols), and you have a method to
securely encrypt and off-load auditing.

    "Rsyslog" supported authentication modes include:
    anon - anonymous authentication
    x509/fingerprint - certificate fingerprint authentication
    x509/certvalid - certificate validation only
    x509/name - certificate validation and subject name authentication.

```
New:
```
Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

RHEL 8 installation media provides "rsyslogd".  "rsyslogd" is a system utility providing support for message logging.  Support for both internet and UNIX domain sockets enables this utility to support both local and remote logging.  Couple this utility with "gnutls" (which is a secure communications library implementing the SSL, TLS and DTLS protocols), and you have a method to securely encrypt and off-load auditing.

"Rsyslog" supported authentication modes include:
anon - anonymous authentication
x509/fingerprint - certificate fingerprint authentication
x509/certvalid - certificate validation only
x509/name - certificate validation and subject name authentication.



```
---
SV-230483:
Old:
```
If security personnel are not notified immediately when storage volume
reaches 75 percent utilization, they are unable to plan for audit record
storage capacity expansion.

```
New:
```
If security personnel are not notified immediately when storage volume reaches 75 percent utilization, they are unable to plan for audit record storage capacity expansion.

```
---
SV-230484:
Old:
```
Inaccurate time stamps make it more difficult to correlate events and
can lead to an inaccurate analysis. Determining the correct time a particular
event occurred on a system is critical when conducting forensic analysis and
investigating system events. Sources outside the configured acceptable
allowance (drift) may be inaccurate.

    Synchronizing internal information system clocks provides uniformity of
time stamps for information systems with multiple system clocks and systems
connected over a network.

    Organizations should consider endpoints that may not have regular access to
the authoritative time server (e.g., mobile, teleworking, and tactical
endpoints).

    If time stamps are not consistently applied and there is no common time
reference, it is difficult to perform forensic analysis.

    Time stamps generated by the operating system include date and time. Time
is commonly expressed in Coordinated Universal Time (UTC), a modern
continuation of Greenwich Mean Time (GMT), or local time with an offset from
UTC.

    RHEL 8 utilizes the "timedatectl" command to view the status of the
"systemd-timesyncd.service". The "timedatectl" status will display the
local time, UTC, and the offset from UTC.

    Note that USNO offers authenticated NTP service to DoD and U.S. Government
agencies operating on the NIPR and SIPR networks. Visit
https://www.usno.navy.mil/USNO/time/ntp/dod-customers for more information.

```
New:
```
Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).

If time stamps are not consistently applied and there is no common time reference, it is difficult to perform forensic analysis.

Time stamps generated by the operating system include date and time. Time is commonly expressed in Coordinated Universal Time (UTC), a modern continuation of Greenwich Mean Time (GMT), or local time with an offset from UTC.

RHEL 8 utilizes the "timedatectl" command to view the status of the "systemd-timesyncd.service". The "timedatectl" status will display the local time, UTC, and the offset from UTC.

Note that USNO offers authenticated NTP service to DoD and U.S. Government agencies operating on the NIPR and SIPR networks. Visit https://www.usno.navy.mil/USNO/time/ntp/dod-customers for more information.



```
---
SV-230485:
Old:
```
Inaccurate time stamps make it more difficult to correlate events and
can lead to an inaccurate analysis. Determining the correct time a particular
event occurred on a system is critical when conducting forensic analysis and
investigating system events. Sources outside the configured acceptable
allowance (drift) may be inaccurate.

    Minimizing the exposure of the server functionality of the chrony daemon
diminishes the attack surface.

    RHEL 8 utilizes the "timedatectl" command to view the status of the
"systemd-timesyncd.service". The "timedatectl" status will display the
local time, UTC, and the offset from UTC.

    Note that USNO offers authenticated NTP service to DoD and U.S. Government
agencies operating on the NIPR and SIPR networks. Visit
https://www.usno.navy.mil/USNO/time/ntp/dod-customers for more information.

```
New:
```
Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Minimizing the exposure of the server functionality of the chrony daemon diminishes the attack surface.

RHEL 8 utilizes the "timedatectl" command to view the status of the "systemd-timesyncd.service". The "timedatectl" status will display the local time, UTC, and the offset from UTC.

Note that USNO offers authenticated NTP service to DOD and U.S. Government agencies operating on the NIPR and SIPR networks. Visit https://www.usno.navy.mil/USNO/time/ntp/DOD-customers for more information.

```
---
SV-230486:
Old:
```
Inaccurate time stamps make it more difficult to correlate events and
can lead to an inaccurate analysis. Determining the correct time a particular
event occurred on a system is critical when conducting forensic analysis and
investigating system events. Sources outside the configured acceptable
allowance (drift) may be inaccurate.

    Not exposing the management interface of the chrony daemon on the network
diminishes the attack space.

    RHEL 8 utilizes the "timedatectl" command to view the status of the
"systemd-timesyncd.service". The "timedatectl" status will display the
local time, UTC, and the offset from UTC.

    Note that USNO offers authenticated NTP service to DoD and U.S. Government
agencies operating on the NIPR and SIPR networks. Visit
https://www.usno.navy.mil/USNO/time/ntp/dod-customers for more information.

```
New:
```
Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Not exposing the management interface of the chrony daemon on the network diminishes the attack space.

RHEL 8 utilizes the "timedatectl" command to view the status of the "systemd-timesyncd.service". The "timedatectl" status will display the local time, UTC, and the offset from UTC.

Note that USNO offers authenticated NTP service to DOD and U.S. Government agencies operating on the NIPR and SIPR networks. Visit https://www.usno.navy.mil/USNO/time/ntp/DOD-customers for more information.

```
---
SV-230487:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Operating systems are capable of providing a wide variety of functions and
services. Some of the functions and services, provided by default, may not be
necessary to support essential organizational operations (e.g., key missions,
functions).

    Examples of non-essential capabilities include, but are not limited to,
games, software packages, tools, and demonstration software not related to
requirements or providing a wide array of functionality not required for every
mission, but which cannot be disabled.

    Verify the operating system is configured to disable non-essential
capabilities. The most secure way of ensuring a non-essential capability is
disabled is to not have the capability installed.

    The telnet service provides an unencrypted remote access service that does
not provide for the confidentiality and integrity of user passwords or the
remote session.

    If a privileged user were to log on using this service, the privileged user
password could be compromised.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of non-essential capabilities include, but are not limited to, games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.

Verify the operating system is configured to disable non-essential capabilities. The most secure way of ensuring a non-essential capability is disabled is to not have the capability installed.

The telnet service provides an unencrypted remote access service that does not provide for the confidentiality and integrity of user passwords or the remote session.

If a privileged user were to log on using this service, the privileged user password could be compromised.

```
---
SV-230488:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Operating systems are capable of providing a wide variety of functions and
services. Some of the functions and services, provided by default, may not be
necessary to support essential organizational operations (e.g., key missions,
functions).

    Examples of non-essential capabilities include, but are not limited to,
games, software packages, tools, and demonstration software not related to
requirements or providing a wide array of functionality not required for every
mission, but which cannot be disabled.

    Verify the operating system is configured to disable non-essential
capabilities. The most secure way of ensuring a non-essential capability is
disabled is to not have the capability installed.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of non-essential capabilities include, but are not limited to, games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.

Verify the operating system is configured to disable non-essential capabilities. The most secure way of ensuring a non-essential capability is disabled is to not have the capability installed.

```
---
SV-230489:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Operating systems are capable of providing a wide variety of functions and
services. Some of the functions and services, provided by default, may not be
necessary to support essential organizational operations (e.g., key missions,
functions).

    Examples of non-essential capabilities include, but are not limited to,
games, software packages, tools, and demonstration software not related to
requirements or providing a wide array of functionality not required for every
mission, but which cannot be disabled.

    Verify the operating system is configured to disable non-essential
capabilities. The most secure way of ensuring a non-essential capability is
disabled is to not have the capability installed.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of non-essential capabilities include, but are not limited to, games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.

Verify the operating system is configured to disable non-essential capabilities. The most secure way of ensuring a non-essential capability is disabled is to not have the capability installed.

```
---
SV-230491:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Operating systems are capable of providing a wide variety of functions and
services. Some of the functions and services, provided by default, may not be
necessary to support essential organizational operations (e.g., key missions,
functions).

    Examples of non-essential capabilities include, but are not limited to,
games, software packages, tools, and demonstration software not related to
requirements or providing a wide array of functionality not required for every
mission, but which cannot be disabled.

    Verify the operating system is configured to disable non-essential
capabilities. The most secure way of ensuring a non-essential capability is
disabled is to not have the capability installed.

    Kernel page-table isolation is a kernel feature that mitigates the Meltdown
security vulnerability and hardens the kernel against attempts to bypass kernel
address space layout randomization (KASLR).

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of non-essential capabilities include, but are not limited to, games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.

Verify the operating system is configured to disable non-essential capabilities. The most secure way of ensuring a non-essential capability is disabled is to not have the capability installed.

Kernel page-table isolation is a kernel feature that mitigates the Meltdown security vulnerability and hardens the kernel against attempts to bypass kernel address space layout randomization (KASLR).

```
---
SV-230492:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Operating systems are capable of providing a wide variety of functions and
services. Some of the functions and services, provided by default, may not be
necessary to support essential organizational operations (e.g., key missions,
functions).

    The rsh-server service provides an unencrypted remote access service that
does not provide for the confidentiality and integrity of user passwords or the
remote session and has very weak authentication.

    If a privileged user were to log on using this service, the privileged user
password could be compromised.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

The rsh-server service provides an unencrypted remote access service that does not provide for the confidentiality and integrity of user passwords or the remote session and has very weak authentication.

If a privileged user were to log on using this service, the privileged user password could be compromised.



```
---
SV-230493:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Failing to disconnect from collaborative computing devices (i.e., cameras)
can result in subsequent compromises of organizational information. Providing
easy methods to physically disconnect from such devices after a collaborative
computing session helps to ensure participants actually carry out the
disconnect activity without having to go through complex and tedious procedures.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Failing to disconnect from collaborative computing devices (i.e., cameras) can result in subsequent compromises of organizational information. Providing easy methods to physically disconnect from such devices after a collaborative computing session helps to ensure participants actually carry out the disconnect activity without having to go through complex and tedious procedures.



```
---
SV-230494:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Failing to disconnect unused protocols can result in a system compromise.

    The Asynchronous Transfer Mode (ATM) is a protocol operating on network,
data link, and physical layers, based on virtual circuits and virtual paths.
Disabling ATM protects the system against exploitation of any laws in its
implementation.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Failing to disconnect unused protocols can result in a system compromise.

The Asynchronous Transfer Mode (ATM) is a protocol operating on network, data link, and physical layers, based on virtual circuits and virtual paths. Disabling ATM protects the system against exploitation of any laws in its implementation.

```
---
SV-230495:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Failing to disconnect unused protocols can result in a system compromise.

    The Controller Area Network (CAN) is a serial communications protocol,
which was initially developed for automotive and is now also used in marine,
industrial, and medical applications. Disabling CAN protects the system against
exploitation of any flaws in its implementation.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Failing to disconnect unused protocols can result in a system compromise.

The Controller Area Network (CAN) is a serial communications protocol, which was initially developed for automotive and is now also used in marine, industrial, and medical applications. Disabling CAN protects the system against exploitation of any flaws in its implementation.

```
---
SV-230496:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Failing to disconnect unused protocols can result in a system compromise.

    The Stream Control Transmission Protocol (SCTP) is a transport layer
protocol, designed to support the idea of message-oriented communication, with
several streams of messages within one connection. Disabling SCTP protects the
system against exploitation of any flaws in its implementation.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Failing to disconnect unused protocols can result in a system compromise.

The Stream Control Transmission Protocol (SCTP) is a transport layer protocol, designed to support the idea of message-oriented communication, with several streams of messages within one connection. Disabling SCTP protects the system against exploitation of any flaws in its implementation.

```
---
SV-230497:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Failing to disconnect unused protocols can result in a system compromise.

    The Transparent Inter-Process Communication (TIPC) protocol is designed to
provide communications between nodes in a cluster. Disabling TIPC protects the
system against exploitation of any flaws in its implementation.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Failing to disconnect unused protocols can result in a system compromise.

The Transparent Inter-Process Communication (TIPC) protocol is designed to provide communications between nodes in a cluster. Disabling TIPC protects the system against exploitation of any flaws in its implementation.

```
---
SV-230498:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Removing support for unneeded filesystem types reduces the local attack
surface of the server.

    Compressed ROM/RAM file system (or cramfs) is a read-only file system
designed for simplicity and space-efficiency.  It is mainly used in embedded
and small-footprint systems.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Removing support for unneeded filesystem types reduces the local attack surface of the server.

Compressed ROM/RAM file system (or cramfs) is a read-only file system designed for simplicity and space-efficiency.  It is mainly used in embedded and small-footprint systems.

```
---
SV-230499:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    The IEEE 1394 (FireWire) is a serial bus standard for high-speed real-time
communication. Disabling FireWire protects the system against exploitation of
any flaws in its implementation.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The IEEE 1394 (FireWire) is a serial bus standard for high-speed real-time communication. Disabling FireWire protects the system against exploitation of any flaws in its implementation.

```
---
SV-230500:
Old:
```
To prevent unauthorized connection of devices, unauthorized transfer
of information, or unauthorized tunneling (i.e., embedding of data types within
data types), organizations must disable or restrict unused or unnecessary
physical and logical ports/protocols on information systems.

    Operating systems are capable of providing a wide variety of functions and
services. Some of the functions and services provided by default may not be
necessary to support essential organizational operations. Additionally, it is
sometimes convenient to provide multiple services from a single component
(e.g., VPN and IPS); however, doing so increases risk over limiting the
services provided by any one component.

    To support the requirements and principles of least functionality, the
operating system must support the organizational requirements, providing only
essential capabilities and limiting the use of ports, protocols, and/or
services to only those required, authorized, and approved to conduct official
business or to address authorized quality-of-life issues.

```
New:
```
To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality-of-life issues.

```
---
SV-230502:
Old:
```
Automatically mounting file systems permits easy introduction of
unknown devices, thereby facilitating malicious activity.

```
New:
```
Automatically mounting file systems permits easy introduction of unknown devices, thereby facilitating malicious activity.

```
---
SV-230503:
Old:
```
USB mass storage permits easy introduction of unknown devices, thereby
facilitating malicious activity.

```
New:
```
USB mass storage permits easy introduction of unknown devices, thereby facilitating malicious activity.



```
---
SV-230504:
Old:
```
Failure to restrict network connectivity only to authorized systems
permits inbound connections from malicious systems. It also permits outbound
connections that may facilitate exfiltration of DoD data.

    RHEL 8 incorporates the "firewalld" daemon, which allows for many
different configurations. One of these configurations is zones. Zones can be
utilized to a deny-all, allow-by-exception approach. The default "drop" zone
will drop all incoming network packets unless it is explicitly allowed by the
configuration file or is related to an outgoing network connection.

```
New:
```
Failure to restrict network connectivity only to authorized systems permits inbound connections from malicious systems. It also permits outbound connections that may facilitate exfiltration of DoD data.

RHEL 8 incorporates the "firewalld" daemon, which allows for many different configurations. One of these configurations is zones. Zones can be utilized to a deny-all, allow-by-exception approach. The default "drop" zone will drop all incoming network packets unless it is explicitly allowed by the configuration file or is related to an outgoing network connection.

```
---
SV-230505:
Old:
```
"Firewalld" provides an easy and effective way to block/limit remote
access to the system via ports, services, and protocols.

    Remote access services, such as those providing remote access to network
devices and information systems, which lack automated control capabilities,
increase risk and make remote user access management difficult at best.

    Remote access is access to DoD nonpublic information systems by an
authorized user (or an information system) communicating through an external,
non-organization-controlled network. Remote access methods include, for
example, dial-up, broadband, and wireless.

    RHEL 8 functionality (e.g., RDP) must be capable of taking enforcement
action if the audit reveals unauthorized activity. Automated control of remote
access sessions allows organizations to ensure ongoing compliance with remote
access policies by enforcing connection rules of remote access applications on
a variety of information system components (e.g., servers, workstations,
notebook computers, smartphones, and tablets).

```
New:
```
"Firewalld" provides an easy and effective way to block/limit remote access to the system via ports, services, and protocols.

Remote access services, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

RHEL 8 functionality (e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).

```
---
SV-230506:
Old:
```
Without protection of communications with wireless peripherals,
confidentiality and integrity may be compromised because unprotected
communications can be intercepted and either read, altered, or used to
compromise the RHEL 8 operating system.

    This requirement applies to wireless peripheral technologies (e.g.,
wireless mice, keyboards, displays, etc.) used with RHEL 8 systems. Wireless
peripherals (e.g., Wi-Fi/Bluetooth/IR Keyboards, Mice, and Pointing Devices and
Near Field Communications [NFC]) present a unique challenge by creating an
open, unsecured port on a computer. Wireless peripherals must meet DoD
requirements for wireless data transmission and be approved for use by the
Authorizing Official (AO). Even though some wireless peripherals, such as mice
and pointing devices, do not ordinarily carry information that need to be
protected, modification of communications with these wireless peripherals may
be used to compromise the RHEL 8 operating system. Communication paths outside
the physical protection of a controlled boundary are exposed to the possibility
of interception and modification.

    Protecting the confidentiality and integrity of communications with
wireless peripherals can be accomplished by physical means (e.g., employing
physical barriers to wireless radio frequencies) or by logical means (e.g.,
employing cryptographic techniques). If physical means of protection are
employed, then logical means (cryptography) do not have to be employed, and
vice versa. If the wireless peripheral is only passing telemetry data,
encryption of the data may not be required.

```
New:
```
Without protection of communications with wireless peripherals, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read, altered, or used to compromise the RHEL 8 operating system.

This requirement applies to wireless peripheral technologies (e.g., wireless mice, keyboards, displays, etc.) used with RHEL 8 systems. Wireless peripherals (e.g., Wi-Fi/Bluetooth/IR Keyboards, Mice, and Pointing Devices and Near Field Communications [NFC]) present a unique challenge by creating an open, unsecured port on a computer. Wireless peripherals must meet DoD requirements for wireless data transmission and be approved for use by the Authorizing Official (AO). Even though some wireless peripherals, such as mice and pointing devices, do not ordinarily carry information that need to be protected, modification of communications with these wireless peripherals may be used to compromise the RHEL 8 operating system. Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.

Protecting the confidentiality and integrity of communications with wireless peripherals can be accomplished by physical means (e.g., employing physical barriers to wireless radio frequencies) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa. If the wireless peripheral is only passing telemetry data, encryption of the data may not be required.



```
---
SV-230507:
Old:
```
Without protection of communications with wireless peripherals,
confidentiality and integrity may be compromised because unprotected
communications can be intercepted and either read, altered, or used to
compromise the RHEL 8 operating system.

    This requirement applies to wireless peripheral technologies (e.g.,
wireless mice, keyboards, displays, etc.) used with RHEL 8 systems. Wireless
peripherals (e.g., Wi-Fi/Bluetooth/IR Keyboards, Mice, and Pointing Devices and
Near Field Communications [NFC]) present a unique challenge by creating an
open, unsecured port on a computer. Wireless peripherals must meet DoD
requirements for wireless data transmission and be approved for use by the
Authorizing Official (AO). Even though some wireless peripherals, such as mice
and pointing devices, do not ordinarily carry information that need to be
protected, modification of communications with these wireless peripherals may
be used to compromise the RHEL 8 operating system. Communication paths outside
the physical protection of a controlled boundary are exposed to the possibility
of interception and modification.

    Protecting the confidentiality and integrity of communications with
wireless peripherals can be accomplished by physical means (e.g., employing
physical barriers to wireless radio frequencies) or by logical means (e.g.,
employing cryptographic techniques). If physical means of protection are
employed, then logical means (cryptography) do not have to be employed, and
vice versa. If the wireless peripheral is only passing telemetry data,
encryption of the data may not be required.

```
New:
```
Without protection of communications with wireless peripherals, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read, altered, or used to compromise the RHEL 8 operating system.

This requirement applies to wireless peripheral technologies (e.g., wireless mice, keyboards, displays, etc.) used with RHEL 8 systems. Wireless peripherals (e.g., Wi-Fi/Bluetooth/IR Keyboards, Mice, and Pointing Devices and Near Field Communications [NFC]) present a unique challenge by creating an open, unsecured port on a computer. Wireless peripherals must meet DoD requirements for wireless data transmission and be approved for use by the Authorizing Official (AO). Even though some wireless peripherals, such as mice and pointing devices, do not ordinarily carry information that need to be protected, modification of communications with these wireless peripherals may be used to compromise the RHEL 8 operating system. Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.

Protecting the confidentiality and integrity of communications with wireless peripherals can be accomplished by physical means (e.g., employing physical barriers to wireless radio frequencies) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa. If the wireless peripheral is only passing telemetry data, encryption of the data may not be required.

```
---
SV-230508:
Old:
```
The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    The "noexec" mount option causes the system to not execute binary files.
This option must be used for mounting any file system not containing approved
binary files, as they may be incompatible. Executing files from untrusted file
systems increases the opportunity for unprivileged users to attain unauthorized
administrative access.

    The "nodev" mount option causes the system to not interpret character or
block special devices. Executing character or block special devices from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access.

    The "nosuid" mount option causes the system to not execute "setuid" and
"setgid" files with owner privileges. This option must be used for mounting
any file system not containing approved "setuid" and "setguid" files.
Executing files from untrusted file systems increases the opportunity for
unprivileged users to attain unauthorized administrative access.

```
New:
```
The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230509:
Old:
```
The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    The "noexec" mount option causes the system to not execute binary files.
This option must be used for mounting any file system not containing approved
binary files, as they may be incompatible. Executing files from untrusted file
systems increases the opportunity for unprivileged users to attain unauthorized
administrative access.
    The "nodev" mount option causes the system to not interpret character or
block special devices. Executing character or block special devices from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access.
    The "nosuid" mount option causes the system to not execute "setuid" and
"setgid" files with owner privileges. This option must be used for mounting
any file system not containing approved "setuid" and "setguid" files.
Executing files from untrusted file systems increases the opportunity for
unprivileged users to attain unauthorized administrative access.

```
New:
```
The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.
The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.
The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230510:
Old:
```
The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    The "noexec" mount option causes the system to not execute binary files.
This option must be used for mounting any file system not containing approved
binary files, as they may be incompatible. Executing files from untrusted file
systems increases the opportunity for unprivileged users to attain unauthorized
administrative access.

    The "nodev" mount option causes the system to not interpret character or
block special devices. Executing character or block special devices from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access.

    The "nosuid" mount option causes the system to not execute "setuid" and
"setgid" files with owner privileges. This option must be used for mounting
any file system not containing approved "setuid" and "setguid" files.
Executing files from untrusted file systems increases the opportunity for
unprivileged users to attain unauthorized administrative access.

```
New:
```
The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230511:
Old:
```
The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    The "noexec" mount option causes the system to not execute binary files.
This option must be used for mounting any file system not containing approved
binary files, as they may be incompatible. Executing files from untrusted file
systems increases the opportunity for unprivileged users to attain unauthorized
administrative access.

    The "nodev" mount option causes the system to not interpret character or
block special devices. Executing character or block special devices from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access.

    The "nosuid" mount option causes the system to not execute "setuid" and
"setgid" files with owner privileges. This option must be used for mounting
any file system not containing approved "setuid" and "setguid" files.
Executing files from untrusted file systems increases the opportunity for
unprivileged users to attain unauthorized administrative access.

```
New:
```
The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230512:
Old:
```
The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    The "noexec" mount option causes the system to not execute binary files.
This option must be used for mounting any file system not containing approved
binary files, as they may be incompatible. Executing files from untrusted file
systems increases the opportunity for unprivileged users to attain unauthorized
administrative access.
    The "nodev" mount option causes the system to not interpret character or
block special devices. Executing character or block special devices from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access.
    The "nosuid" mount option causes the system to not execute "setuid" and
"setgid" files with owner privileges. This option must be used for mounting
any file system not containing approved "setuid" and "setguid" files.
Executing files from untrusted file systems increases the opportunity for
unprivileged users to attain unauthorized administrative access.

```
New:
```
The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.
The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.
The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230513:
Old:
```
The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    The "noexec" mount option causes the system to not execute binary files.
This option must be used for mounting any file system not containing approved
binary files, as they may be incompatible. Executing files from untrusted file
systems increases the opportunity for unprivileged users to attain unauthorized
administrative access.

    The "nodev" mount option causes the system to not interpret character or
block special devices. Executing character or block special devices from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access.

    The "nosuid" mount option causes the system to not execute "setuid" and
"setgid" files with owner privileges. This option must be used for mounting
any file system not containing approved "setuid" and "setguid" files.
Executing files from untrusted file systems increases the opportunity for
unprivileged users to attain unauthorized administrative access.

```
New:
```
The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230514:
Old:
```
The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    The "noexec" mount option causes the system to not execute binary files.
This option must be used for mounting any file system not containing approved
binary files, as they may be incompatible. Executing files from untrusted file
systems increases the opportunity for unprivileged users to attain unauthorized
administrative access.

    The "nodev" mount option causes the system to not interpret character or
block special devices. Executing character or block special devices from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access.

    The "nosuid" mount option causes the system to not execute "setuid" and
"setgid" files with owner privileges. This option must be used for mounting
any file system not containing approved "setuid" and "setguid" files.
Executing files from untrusted file systems increases the opportunity for
unprivileged users to attain unauthorized administrative access.

```
New:
```
The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230515:
Old:
```
The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    The "noexec" mount option causes the system to not execute binary files.
This option must be used for mounting any file system not containing approved
binary files, as they may be incompatible. Executing files from untrusted file
systems increases the opportunity for unprivileged users to attain unauthorized
administrative access.

    The "nodev" mount option causes the system to not interpret character or
block special devices. Executing character or block special devices from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access.

    The "nosuid" mount option causes the system to not execute "setuid" and
"setgid" files with owner privileges. This option must be used for mounting
any file system not containing approved "setuid" and "setguid" files.
Executing files from untrusted file systems increases the opportunity for
unprivileged users to attain unauthorized administrative access.

```
New:
```
The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230516:
Old:
```
The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    The "noexec" mount option causes the system to not execute binary files.
This option must be used for mounting any file system not containing approved
binary files, as they may be incompatible. Executing files from untrusted file
systems increases the opportunity for unprivileged users to attain unauthorized
administrative access.

    The "nodev" mount option causes the system to not interpret character or
block special devices. Executing character or block special devices from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access.

    The "nosuid" mount option causes the system to not execute "setuid" and
"setgid" files with owner privileges. This option must be used for mounting
any file system not containing approved "setuid" and "setguid" files.
Executing files from untrusted file systems increases the opportunity for
unprivileged users to attain unauthorized administrative access.

```
New:
```
The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230517:
Old:
```
The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    The "noexec" mount option causes the system to not execute binary files.
This option must be used for mounting any file system not containing approved
binary files, as they may be incompatible. Executing files from untrusted file
systems increases the opportunity for unprivileged users to attain unauthorized
administrative access.

    The "nodev" mount option causes the system to not interpret character or
block special devices. Executing character or block special devices from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access.

    The "nosuid" mount option causes the system to not execute "setuid" and
"setgid" files with owner privileges. This option must be used for mounting
any file system not containing approved "setuid" and "setguid" files.
Executing files from untrusted file systems increases the opportunity for
unprivileged users to attain unauthorized administrative access.

```
New:
```
The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230518:
Old:
```
The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    The "noexec" mount option causes the system to not execute binary files.
This option must be used for mounting any file system not containing approved
binary files, as they may be incompatible. Executing files from untrusted file
systems increases the opportunity for unprivileged users to attain unauthorized
administrative access.

    The "nodev" mount option causes the system to not interpret character or
block special devices. Executing character or block special devices from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access.

    The "nosuid" mount option causes the system to not execute "setuid" and
"setgid" files with owner privileges. This option must be used for mounting
any file system not containing approved "setuid" and "setguid" files.
Executing files from untrusted file systems increases the opportunity for
unprivileged users to attain unauthorized administrative access.

```
New:
```
The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230519:
Old:
```
The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    The "noexec" mount option causes the system to not execute binary files.
This option must be used for mounting any file system not containing approved
binary files, as they may be incompatible. Executing files from untrusted file
systems increases the opportunity for unprivileged users to attain unauthorized
administrative access.

    The "nodev" mount option causes the system to not interpret character or
block special devices. Executing character or block special devices from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access.

    The "nosuid" mount option causes the system to not execute "setuid" and
"setgid" files with owner privileges. This option must be used for mounting
any file system not containing approved "setuid" and "setguid" files.
Executing files from untrusted file systems increases the opportunity for
unprivileged users to attain unauthorized administrative access.

```
New:
```
The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230520:
Old:
```
The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    The "noexec" mount option causes the system to not execute binary files.
This option must be used for mounting any file system not containing approved
binary files, as they may be incompatible. Executing files from untrusted file
systems increases the opportunity for unprivileged users to attain unauthorized
administrative access.

    The "nodev" mount option causes the system to not interpret character or
block special devices. Executing character or block special devices from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access.

    The "nosuid" mount option causes the system to not execute "setuid" and
"setgid" files with owner privileges. This option must be used for mounting
any file system not containing approved "setuid" and "setguid" files.
Executing files from untrusted file systems increases the opportunity for
unprivileged users to attain unauthorized administrative access.

```
New:
```
The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230521:
Old:
```
The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    The "noexec" mount option causes the system to not execute binary files.
This option must be used for mounting any file system not containing approved
binary files, as they may be incompatible. Executing files from untrusted file
systems increases the opportunity for unprivileged users to attain unauthorized
administrative access.

    The "nodev" mount option causes the system to not interpret character or
block special devices. Executing character or block special devices from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access.

    The "nosuid" mount option causes the system to not execute "setuid" and
"setgid" files with owner privileges. This option must be used for mounting
any file system not containing approved "setuid" and "setguid" files.
Executing files from untrusted file systems increases the opportunity for
unprivileged users to attain unauthorized administrative access.

```
New:
```
The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230522:
Old:
```
The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    The "noexec" mount option causes the system to not execute binary files.
This option must be used for mounting any file system not containing approved
binary files, as they may be incompatible. Executing files from untrusted file
systems increases the opportunity for unprivileged users to attain unauthorized
administrative access.

    The "nodev" mount option causes the system to not interpret character or
block special devices. Executing character or block special devices from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access.

    The "nosuid" mount option causes the system to not execute "setuid" and
"setgid" files with owner privileges. This option must be used for mounting
any file system not containing approved "setuid" and "setguid" files.
Executing files from untrusted file systems increases the opportunity for
unprivileged users to attain unauthorized administrative access.

```
New:
```
The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-230523:
Old:
```
The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    Utilizing a whitelist provides a configuration management method for
allowing the execution of only authorized software. Using only authorized
software decreases risk by limiting the number of potential vulnerabilities.
Verification of whitelisted software occurs prior to execution or at system
startup.

    User home directories/folders may contain information of a sensitive
nature. Non-privileged users should coordinate any sharing of information with
an SA through shared resources.

    RHEL 8 ships with many optional packages. One such package is a file access
policy daemon called "fapolicyd". "fapolicyd" is a userspace daemon that
determines access rights to files based on attributes of the process and file.
It can be used to either blacklist or whitelist processes or file access.

    Proceed with caution with enforcing the use of this daemon. Improper
configuration may render the system non-functional. The "fapolicyd" API is
not namespace aware and can cause issues when launching or running containers.

```
New:
```
The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

Utilizing a whitelist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities. Verification of whitelisted software occurs prior to execution or at system startup.

User home directories/folders may contain information of a sensitive nature. Non-privileged users should coordinate any sharing of information with an SA through shared resources.

RHEL 8 ships with many optional packages. One such package is a file access policy daemon called "fapolicyd". "fapolicyd" is a userspace daemon that determines access rights to files based on attributes of the process and file. It can be used to either blacklist or whitelist processes or file access.

Proceed with caution with enforcing the use of this daemon. Improper configuration may render the system non-functional. The "fapolicyd" API is not namespace aware and can cause issues when launching or running containers.



```
---
SV-230524:
Old:
```
Without authenticating devices, unidentified or unknown devices may be
introduced, thereby facilitating malicious activity.

    Peripherals include, but are not limited to, such devices as flash drives,
external storage, and printers.

    A new feature that RHEL 8 provides is the USBGuard software framework. The
USBguard-daemon is the main component of the USBGuard software framework. It
runs as a service in the background and enforces the USB device authorization
policy for all USB devices. The policy is defined by a set of rules using a
rule language described in the usbguard-rules.conf file. The policy and the
authorization state of USB devices can be modified during runtime using the
usbguard tool.

    The System Administrator (SA) must work with the site Information System
Security Officer (ISSO) to determine a list of authorized peripherals and
establish rules within the USBGuard software framework to allow only authorized
devices.

```
New:
```
Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Peripherals include, but are not limited to, such devices as flash drives, external storage, and printers.

A new feature that RHEL 8 provides is the USBGuard software framework. The USBguard-daemon is the main component of the USBGuard software framework. It runs as a service in the background and enforces the USB device authorization policy for all USB devices. The policy is defined by a set of rules using a rule language described in the usbguard-rules.conf file. The policy and the authorization state of USB devices can be modified during runtime using the usbguard tool.

The System Administrator (SA) must work with the site Information System Security Officer (ISSO) to determine a list of authorized peripherals and establish rules within the USBGuard software framework to allow only authorized devices.

```
---
SV-230525:
Old:
```
DoS is a condition when a resource is not available for legitimate
users. When this occurs, the organization either cannot accomplish its mission
or must operate at degraded capacity.

    This requirement addresses the configuration of RHEL 8 to mitigate the
impact of DoS attacks that have occurred or are ongoing on system availability.
For each system, known and potential DoS attacks must be identified and
solutions for each type implemented. A variety of technologies exists to limit
or, in some cases, eliminate the effects of DoS attacks (e.g., limiting
processes or establishing memory partitions). Employing increased capacity and
bandwidth, combined with service redundancy, may reduce the susceptibility to
some DoS attacks.

    Since version 0.6.0, "firewalld" has incorporated "nftables" as its
backend support. Utilizing the limit statement in "nftables" can help to
mitigate DoS attacks.

```
New:
```
DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of RHEL 8 to mitigate the impact of DoS attacks that have occurred or are ongoing on system availability. For each system, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exists to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing memory partitions). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

Since version 0.6.0, "firewalld" has incorporated "nftables" as its backend support. Utilizing the limit statement in "nftables" can help to mitigate DoS attacks.

```
---
SV-230526:
Old:
```
Without protection of the transmitted information, confidentiality and
integrity may be compromised because unprotected communications can be
intercepted and either read or altered.

    This requirement applies to both internal and external networks and all
types of information system components from which information can be
transmitted (e.g., servers, mobile devices, notebook computers, printers,
copiers, scanners, and facsimile machines). Communication paths outside the
physical protection of a controlled boundary are exposed to the possibility of
interception and modification.

    Protecting the confidentiality and integrity of organizational information
can be accomplished by physical means (e.g., employing physical distribution
systems) or by logical means (e.g., employing cryptographic techniques). If
physical means of protection are employed, then logical means (cryptography) do
not have to be employed, and vice versa.

```
New:
```
Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered. 

This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. 

Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.



```
---
SV-230527:
Old:
```
Without protection of the transmitted information, confidentiality and
integrity may be compromised because unprotected communications can be
intercepted and either read or altered.

    This requirement applies to both internal and external networks and all
types of information system components from which information can be
transmitted (e.g., servers, mobile devices, notebook computers, printers,
copiers, scanners, and facsimile machines). Communication paths outside the
physical protection of a controlled boundary are exposed to the possibility of
interception and modification.

    Protecting the confidentiality and integrity of organizational information
can be accomplished by physical means (e.g., employing physical distribution
systems) or by logical means (e.g., employing cryptographic techniques). If
physical means of protection are employed, then logical means (cryptography) do
not have to be employed, and vice versa.

    Session key regeneration limits the chances of a session key becoming
compromised.

```
New:
```
Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered. 

This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. 

Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.

Session key regeneration limits the chances of a session key becoming compromised.



```
---
SV-230529:
Old:
```
A locally logged-on user, who presses Ctrl-Alt-Delete when at the
console, can reboot the system. If accidentally pressed, as could happen in the
case of a mixed OS environment, this can create the risk of short-term loss of
availability of systems due to unintentional reboot. In a graphical user
environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is
reduced because the user will be prompted before any action is taken.

```
New:
```
A locally logged-on user, who presses Ctrl-Alt-Delete when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In a graphical user environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.

```
---
SV-230530:
Old:
```
A locally logged-on user, who presses Ctrl-Alt-Delete, when at the
console, can reboot the system. If accidentally pressed, as could happen in the
case of a mixed OS environment, this can create the risk of short-term loss of
availability of systems due to unintentional reboot. In a graphical user
environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is
reduced because the user will be prompted before any action is taken.

```
New:
```
A locally logged-on user, who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In a graphical user environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.

```
---
SV-230531:
Old:
```
A locally logged-on user who presses Ctrl-Alt-Delete when at the
console can reboot the system. If accidentally pressed, as could happen in the
case of a mixed OS environment, this can create the risk of short-term loss of
availability of systems due to unintentional reboot. In a graphical user
environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is
reduced because the user will be prompted before any action is taken.

```
New:
```
A locally logged-on user who presses Ctrl-Alt-Delete when at the console can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In a graphical user environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.

```
---
SV-230532:
Old:
```
The debug-shell requires no authentication and provides root
privileges to anyone who has physical access to the machine.  While this
feature is disabled by default, masking it adds an additional layer of
assurance that it will not be enabled via a dependency in systemd.  This also
prevents attackers with physical access from trivially bypassing security on
the machine through valid troubleshooting configurations and gaining root
access when the system is rebooted.

```
New:
```
The debug-shell requires no authentication and provides root privileges to anyone who has physical access to the machine.  While this feature is disabled by default, masking it adds an additional layer of assurance that it will not be enabled via a dependency in systemd.  This also prevents attackers with physical access from trivially bypassing security on the machine through valid troubleshooting configurations and gaining root access when the system is rebooted.

```
---
SV-230533:
Old:
```
If TFTP is required for operational support (such as the transmission
of router configurations) its use must be documented with the Information
System Security Officer (ISSO), restricted to only authorized personnel, and
have access control rules established.

```
New:
```
If TFTP is required for operational support (such as the transmission of router configurations) its use must be documented with the Information System Security Officer (ISSO), restricted to only authorized personnel, and have access control rules established.

```
---
SV-230534:
Old:
```
If an account other than root also has a User Identifier (UID) of
"0", it has root authority, giving that account unrestricted access to the
entire operating system. Multiple accounts with a UID of "0" afford an
opportunity for potential intruders to guess a password for a privileged
account.

```
New:
```
If an account other than root also has a User Identifier (UID) of "0", it has root authority, giving that account unrestricted access to the entire operating system. Multiple accounts with a UID of "0" afford an opportunity for potential intruders to guess a password for a privileged account.

```
---
SV-230535:
Old:
```
ICMP redirect messages are used by routers to inform hosts that a more
direct route exists for a particular destination. These messages modify the
host's route table and are unauthenticated. An illicit ICMP redirect message
could result in a man-in-the-middle attack.

```
New:
```
ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-230536:
Old:
```
ICMP redirect messages are used by routers to inform hosts that a more
direct route exists for a particular destination. These messages contain
information from the system's route table, possibly revealing portions of the
network topology.

    There are notable differences between Internet Protocol version 4 (IPv4)
and Internet Protocol version 6 (IPv6). There is only a directive to disable
sending of IPv4 redirected packets. Refer to RFC4294 for an explanation of
"IPv6 Node Requirements", which resulted in this difference between IPv4 and
IPv6.

```
New:
```
ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table, possibly revealing portions of the network topology.

There are notable differences between Internet Protocol version 4 (IPv4) and Internet Protocol version 6 (IPv6). There is only a directive to disable sending of IPv4 redirected packets. Refer to RFC4294 for an explanation of "IPv6 Node Requirements", which resulted in this difference between IPv4 and IPv6.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-230537:
Old:
```
Responding to broadcast ICMP echoes facilitates network mapping and
provides a vector for amplification attacks.

    There are notable differences between Internet Protocol version 4 (IPv4)
and Internet Protocol version 6 (IPv6). IPv6 does not implement the same method
of broadcast as IPv4. Instead, IPv6 uses multicast addressing to the all-hosts
multicast group. Refer to RFC4294 for an explanation of "IPv6 Node
Requirements", which resulted in this difference between IPv4 and IPv6.

```
New:
```
Responding to broadcast ICMP echoes facilitates network mapping and provides a vector for amplification attacks.

There are notable differences between Internet Protocol version 4 (IPv4) and Internet Protocol version 6 (IPv6). IPv6 does not implement the same method of broadcast as IPv4. Instead, IPv6 uses multicast addressing to the all-hosts multicast group. Refer to RFC4294 for an explanation of "IPv6 Node Requirements", which resulted in this difference between IPv4 and IPv6.
The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-230538:
Old:
```
Source-routed packets allow the source of the packet to suggest that
routers forward the packet along a different path than configured on the
router, which can be used to bypass network security measures. This requirement
applies only to the forwarding of source-routed traffic, such as when
forwarding is enabled and the system is functioning as a router.

```
New:
```
Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when forwarding is enabled and the system is functioning as a router.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-230539:
Old:
```
Source-routed packets allow the source of the packet to suggest that
routers forward the packet along a different path than configured on the
router, which can be used to bypass network security measures. This requirement
applies only to the forwarding of source-routed traffic, such as when
forwarding is enabled and the system is functioning as a router.

```
New:
```
Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when forwarding is enabled and the system is functioning as a router.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-230540:
Old:
```
Routing protocol daemons are typically used on routers to exchange
network topology information with other routers. If this software is used when
not required, system network information may be unnecessarily transmitted
across the network.

```
New:
```
Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-230541:
Old:
```
Routing protocol daemons are typically used on routers to exchange
network topology information with other routers. If this software is used when
not required, system network information may be unnecessarily transmitted
across the network.

    An illicit router advertisement message could result in a man-in-the-middle
attack.

```
New:
```
Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.

An illicit router advertisement message could result in a man-in-the-middle attack.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-230542:
Old:
```
Routing protocol daemons are typically used on routers to exchange
network topology information with other routers. If this software is used when
not required, system network information may be unnecessarily transmitted
across the network.

    An illicit router advertisement message could result in a man-in-the-middle
attack.

```
New:
```
Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.

An illicit router advertisement message could result in a man-in-the-middle attack.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-230543:
Old:
```
ICMP redirect messages are used by routers to inform hosts that a more
direct route exists for a particular destination. These messages contain
information from the system's route table, possibly revealing portions of the
network topology.

    There are notable differences between Internet Protocol version 4 (IPv4)
and Internet Protocol version 6 (IPv6). There is only a directive to disable
sending of IPv4 redirected packets. Refer to RFC4294 for an explanation of
"IPv6 Node Requirements", which resulted in this difference between IPv4 and
IPv6.

```
New:
```
ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table, possibly revealing portions of the network topology.

There are notable differences between Internet Protocol version 4 (IPv4) and Internet Protocol version 6 (IPv6). There is only a directive to disable sending of IPv4 redirected packets. Refer to RFC4294 for an explanation of "IPv6 Node Requirements", which resulted in this difference between IPv4 and IPv6.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-230544:
Old:
```
ICMP redirect messages are used by routers to inform hosts that a more
direct route exists for a particular destination. These messages modify the
host's route table and are unauthenticated. An illicit ICMP redirect message
could result in a man-in-the-middle attack.

```
New:
```
ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-230545:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-230546:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-230547:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-230548:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    User namespaces are used primarily for Linux container.  The value 0
disallows the use of user namespaces.  When containers are not in use,
namespaces should be disallowed.  When containers are deployed on a system, the
value should be set to a large non-zero value.  The default value is 7182.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-230549:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Enabling reverse path filtering drops packets with source addresses that
are not routable.  There is not an equivalent filter for IPv6 traffic.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-230550:
Old:
```
If unrestricted mail relaying is permitted, unauthorized senders could
use this host as a mail relay for the purpose of sending spam or other
unauthorized activity.

```
New:
```
If unrestricted mail relaying is permitted, unauthorized senders could use this host as a mail relay for the purpose of sending spam or other unauthorized activity.

```
---
SV-230551:
Old:
```
Extended attributes in file systems are used to contain arbitrary data
and file metadata with security implications.

    RHEL 8 installation media come with a file integrity tool, Advanced
Intrusion Detection Environment (AIDE).

```
New:
```
Extended attributes in file systems are used to contain arbitrary data and file metadata with security implications.

RHEL 8 installation media come with a file integrity tool, Advanced Intrusion Detection Environment (AIDE).

```
---
SV-230552:
Old:
```
ACLs can provide permissions beyond those permitted through the file
mode and must be verified by file integrity tools.

    RHEL 8 installation media come with a file integrity tool, Advanced
Intrusion Detection Environment (AIDE).

```
New:
```
ACLs can provide permissions beyond those permitted through the file mode and must be verified by file integrity tools.

RHEL 8 installation media come with a file integrity tool, Advanced Intrusion Detection Environment (AIDE).

```
---
SV-230553:
Old:
```
Internet services that are not required for system or application
processes must not be active to decrease the attack surface of the system.
Graphical display managers have a long history of security vulnerabilities and
must not be used, unless approved and documented.

```
New:
```
Internet services that are not required for system or application processes must not be active to decrease the attack surface of the system. Graphical display managers have a long history of security vulnerabilities and must not be used, unless approved and documented.

```
---
SV-230554:
Old:
```
Network interfaces in promiscuous mode allow for the capture of all
network traffic visible to the system. If unauthorized individuals can access
these applications, it may allow them to collect information such as logon IDs,
passwords, and key exchanges between systems.

    If the system is being used to perform a network troubleshooting function,
the use of these tools must be documented with the Information System Security
Officer (ISSO) and restricted to only authorized personnel.

```
New:
```
Network interfaces in promiscuous mode allow for the capture of all network traffic visible to the system. If unauthorized individuals can access these applications, it may allow them to collect information such as logon IDs, passwords, and key exchanges between systems.

If the system is being used to perform a network troubleshooting function, the use of these tools must be documented with the Information System Security Officer (ISSO) and restricted to only authorized personnel.

```
---
SV-230555:
Old:
```
The security risk of using X11 forwarding is that the client's X11
display server may be exposed to attack when the SSH client requests
forwarding.  A system administrator may have a stance in which they want to
protect clients that may expose themselves to attack by unwittingly requesting
X11 forwarding, which can warrant a "no" setting.

    X11 forwarding should be enabled with caution. Users with the ability to
bypass file permissions on the remote host (for the user's X11 authorization
database) can access the local X11 display through the forwarded connection. An
attacker may then be able to perform activities such as keystroke monitoring if
the ForwardX11Trusted option is also enabled.

    If X11 services are not required for the system's intended function, they
should be disabled or restricted as appropriate to the system’s needs.

```
New:
```
The security risk of using X11 forwarding is that the client's X11 display server may be exposed to attack when the SSH client requests forwarding.  A system administrator may have a stance in which they want to protect clients that may expose themselves to attack by unwittingly requesting X11 forwarding, which can warrant a "no" setting.

X11 forwarding should be enabled with caution. Users with the ability to bypass file permissions on the remote host (for the user's X11 authorization database) can access the local X11 display through the forwarded connection. An attacker may then be able to perform activities such as keystroke monitoring if the ForwardX11Trusted option is also enabled.

If X11 services are not required for the system's intended function, they should be disabled or restricted as appropriate to the system’s needs.

```
---
SV-230556:
Old:
```
When X11 forwarding is enabled, there may be additional exposure to
the server and client displays if the sshd proxy display is configured to
listen on the wildcard address.  By default, sshd binds the forwarding server
to the loopback address and sets the hostname part of the DIPSLAY environment
variable to localhost.  This prevents remote hosts from connecting to the proxy
display.

```
New:
```
When X11 forwarding is enabled, there may be additional exposure to the server and client displays if the sshd proxy display is configured to listen on the wildcard address.  By default, sshd binds the forwarding server to the loopback address and sets the hostname part of the DIPSLAY environment variable to localhost.  This prevents remote hosts from connecting to the proxy display.

```
---
SV-230557:
Old:
```
Restricting TFTP to a specific directory prevents remote users from
copying, transferring, or overwriting system files.

```
New:
```
Restricting TFTP to a specific directory prevents remote users from copying, transferring, or overwriting system files.

```
---
SV-230558:
Old:
```
The FTP service provides an unencrypted remote access that does not
provide for the confidentiality and integrity of user passwords or the remote
session. If a privileged user were to log on using this service, the privileged
user password could be compromised. SSH or other encrypted file transfer
methods must be used in place of this service.

```
New:
```
The FTP service provides an unencrypted remote access that does not provide for the confidentiality and integrity of user passwords or the remote session. If a privileged user were to log on using this service, the privileged user password could be compromised. SSH or other encrypted file transfer methods must be used in place of this service.

```
---
SV-230559:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Operating systems are capable of providing a wide variety of functions and
services. Some of the functions and services, provided by default, may not be
necessary to support essential organizational operations (e.g., key missions,
functions).

    The gssproxy package is a proxy for GSS API credential handling and could
expose secrets on some networks. It is not needed for normal function of the OS.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

The gssproxy package is a proxy for GSS API credential handling and could expose secrets on some networks. It is not needed for normal function of the OS.

```
---
SV-230560:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Operating systems are capable of providing a wide variety of functions and
services. Some of the functions and services, provided by default, may not be
necessary to support essential organizational operations (e.g., key missions,
functions).

    The iprutils package provides a suite of utilities to manage and configure
SCSI devices supported by the ipr SCSI storage device driver.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

The iprutils package provides a suite of utilities to manage and configure SCSI devices supported by the ipr SCSI storage device driver.

```
---
SV-230561:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Operating systems are capable of providing a wide variety of functions and
services. Some of the functions and services, provided by default, may not be
necessary to support essential organizational operations (e.g., key missions,
functions).

    The tuned package contains a daemon that tunes the system settings
dynamically. It does so by monitoring the usage of several system components
periodically. Based on that information, components will then be put into lower
or higher power savings modes to adapt to the current usage. The tuned package
is not needed for normal OS operations.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

The tuned package contains a daemon that tunes the system settings dynamically. It does so by monitoring the usage of several system components periodically. Based on that information, components will then be put into lower or higher power savings modes to adapt to the current usage. The tuned package is not needed for normal OS operations.

```
---
SV-237640:
Old:
```
Unapproved mechanisms that are used for authentication to the
cryptographic module are not verified and therefore cannot be relied upon to
provide confidentiality or integrity, and DoD data may be compromised.

    RHEL 8 systems utilizing encryption are required to use FIPS-compliant
mechanisms for authenticating to cryptographic modules.

    Currently, Kerberos does not utilize FIPS 140-2 cryptography.

    FIPS 140-2 is the current standard for validating that mechanisms used to
access cryptographic modules utilize authentication that meets DoD
requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a
general-purpose computing system.

```
New:
```
Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

RHEL 8 systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

Currently, Kerberos does not utilize FIPS 140-2 cryptography.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general-purpose computing system.

```
---
SV-237641:
Old:
```
The sudo command allows a user to execute programs with elevated
(administrator) privileges. It prompts the user for their password and confirms
your request to execute a command by checking a file, called sudoers. If the
"sudoers" file is not configured correctly, any user defined on the system
can initiate privileged actions on the target system.

```
New:
```
The sudo command allows a user to execute programs with elevated (administrator) privileges. It prompts the user for their password and confirms your request to execute a command by checking a file, called sudoers. If the "sudoers" file is not configured correctly, any user defined on the system can initiate privileged actions on the target system.

```
---
SV-237642:
Old:
```
The sudoers security policy requires that users authenticate
themselves before they can use sudo. When sudoers requires authentication, it
validates the invoking user's credentials. If the rootpw, targetpw, or runaspw
flags are defined and not disabled, by default the operating system will prompt
the invoking user for the "root" user password.
    For more information on each of the listed configurations, reference the
sudoers(5) manual page.

```
New:
```
The sudoers security policy requires that users authenticate themselves before they can use sudo. When sudoers requires authentication, it validates the invoking user's credentials. If the rootpw, targetpw, or runaspw flags are defined and not disabled, by default the operating system will prompt the invoking user for the "root" user password. 
For more information on each of the listed configurations, reference the sudoers(5) manual page.

```
---
SV-237643:
Old:
```
Without re-authentication, users may access resources or perform tasks
for which they do not have authorization.

    When operating systems provide the capability to escalate a functional
capability, it is critical the organization requires the user to
re-authenticate when using the "sudo" command.

    If the value is set to an integer less than 0, the user's time stamp will
not expire and the user will not have to re-authenticate for privileged actions
until the user's session is terminated.

```
New:
```
Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 

When operating systems provide the capability to escalate a functional capability, it is critical the organization requires the user to re-authenticate when using the "sudo" command.

If the value is set to an integer less than 0, the user's time stamp will not expire and the user will not have to re-authenticate for privileged actions until the user's session is terminated.

```
---
SV-244519:
Old:
```
Display of a standardized and approved use notification before
granting access to the operating system ensures privacy and security
notification verbiage used is consistent with applicable federal laws,
Executive Orders, directives, policies, regulations, standards, and guidance.

    System use notifications are required only for access via logon interfaces
with human users and are not required when such human interfaces do not exist.

```
New:
```
Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.



```
---
SV-244521:
Old:
```
If the system does not require valid authentication before it boots
into single-user or maintenance mode, anyone who invokes single-user or
maintenance mode is granted privileged access to all files on the system. GRUB
2 is the default boot loader for RHEL 8 and is designed to require a password
to boot into single-user mode or make modifications to the boot menu.

```
New:
```
If the system does not require valid authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 8 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.

The GRUB 2 superuser account is an account of last resort. Establishing a unique username for this account hardens the boot loader against brute force attacks. Due to the nature of the superuser account database being distinct from the OS account database, this allows the use of a username that is not among those within the OS account database. Examples of non-unique superusers names are root, superuser, unlock, etc.

```
---
SV-244522:
Old:
```
If the system does not require valid authentication before it boots
into single-user or maintenance mode, anyone who invokes single-user or
maintenance mode is granted privileged access to all files on the system. GRUB
2 is the default boot loader for RHEL 8 and is designed to require a password
to boot into single-user mode or make modifications to the boot menu.

```
New:
```
If the system does not require valid authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 8 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.

The GRUB 2 superuser account is an account of last resort. Establishing a unique username for this account hardens the boot loader against brute force attacks. Due to the nature of the superuser account database being distinct from the OS account database, this allows the use of a username that is not among those within the OS account database. Examples of non-unique superusers names are root, superuser, unlock, etc.

```
---
SV-244523:
Old:
```
If the system does not require valid root authentication before it
boots into emergency or rescue mode, anyone who invokes emergency or rescue
mode is granted privileged access to all files on the system.

```
New:
```
If the system does not require valid root authentication before it boots into emergency or rescue mode, anyone who invokes emergency or rescue mode is granted privileged access to all files on the system.

```
---
SV-244524:
Old:
```
Unapproved mechanisms that are used for authentication to the
cryptographic module are not verified and therefore cannot be relied upon to
provide confidentiality or integrity, and DoD data may be compromised.

    RHEL 8 systems utilizing encryption are required to use FIPS-compliant
mechanisms for authenticating to cryptographic modules.

    FIPS 140-2 is the current standard for validating that mechanisms used to
access cryptographic modules utilize authentication that meets DoD
requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a
general-purpose computing system.

```
New:
```
Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

RHEL 8 systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules. 

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general-purpose computing system.

```
---
SV-244525:
Old:
```
Terminating an idle SSH session within a short time period reduces the
window of opportunity for unauthorized personnel to take control of a
management session enabled on the console or console port that has been left
unattended. In addition, quickly terminating an idle SSH session will also free
up resources committed by the managed network element.

    Terminating network connections associated with communications sessions
includes, for example, de-allocating associated TCP/IP address/port pairs at
the operating system level and de-allocating networking assignments at the
application level if multiple application sessions are using a single operating
system-level network connection. This does not mean that the operating system
terminates all sessions or network access; it only ends the inactive session
and releases the resources associated with that session.

    RHEL 8 utilizes /etc/ssh/sshd_config for configurations of OpenSSH. Within
the sshd_config the product of the values of "ClientAliveInterval" and
"ClientAliveCountMax" are used to establish the inactivity threshold. The
"ClientAliveInterval" is a timeout interval in seconds after which if no data
has been received from the client, sshd will send a message through the
encrypted channel to request a response from the client. The
"ClientAliveCountMax" is the number of client alive messages that may be sent
without sshd receiving any messages back from the client. If this threshold is
met, sshd will disconnect the client. For more information on these settings
and others, refer to the sshd_config man pages.

```
New:
```
Terminating an unresponsive SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, deallocating associated TCP/IP address/port pairs at the operating system level and deallocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the unresponsive session and releases the resources associated with that session.

RHEL 8 uses /etc/ssh/sshd_config for configurations of OpenSSH. Within the sshd_config, the product of the values of "ClientAliveInterval" and "ClientAliveCountMax" is used to establish the inactivity threshold. The "ClientAliveInterval" is a timeout interval in seconds after which if no data has been received from the client, sshd will send a message through the encrypted channel to request a response from the client. The "ClientAliveCountMax" is the number of client alive messages that may be sent without sshd receiving any messages back from the client. If this threshold is met, sshd will disconnect the client. For more information on these settings and others, refer to the sshd_config man pages.



```
---
SV-244526:
Old:
```
Without cryptographic integrity protections, information can be
altered by unauthorized users without detection.

    Remote access (e.g., RDP) is access to DoD nonpublic information systems by
an authorized user (or an information system) communicating through an
external, non-organization-controlled network. Remote access methods include,
for example, dial-up, broadband, and wireless.

    Cryptographic mechanisms used for protecting the integrity of information
include, for example, signed hash functions using asymmetric cryptography
enabling distribution of the public key to verify the hash information while
maintaining the confidentiality of the secret key used to generate the hash.

    RHEL 8 incorporates system-wide crypto policies by default. The SSH
configuration file has no effect on the ciphers, MACs, or algorithms unless
specifically defined in the /etc/sysconfig/sshd file. The employed algorithms
can be viewed in the /etc/crypto-policies/back-ends/ directory.

```
New:
```
Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

RHEL 8 incorporates system-wide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the /etc/sysconfig/sshd file. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/ directory.



```
---
SV-244527:
Old:
```
The most important characteristic of a random number generator is its
randomness, namely its ability to deliver random numbers that are impossible to
predict.  Entropy in computer security is associated with the unpredictability
of a source of randomness.  The random source with high entropy tends to
achieve a uniform distribution of random values.  Random number generators are
one of the most important building blocks of cryptosystems.

    The rngd service feeds random data from hardware device to kernel random
device. Quality (non-predictable) random number generation is important for
several security functions (i.e., ciphers).

```
New:
```
The most important characteristic of a random number generator is its randomness, namely its ability to deliver random numbers that are impossible to predict.  Entropy in computer security is associated with the unpredictability of a source of randomness.  The random source with high entropy tends to achieve a uniform distribution of random values.  Random number generators are one of the most important building blocks of cryptosystems.  

The rngd service feeds random data from hardware device to kernel random device. Quality (non-predictable) random number generation is important for several security functions (i.e., ciphers).

```
---
SV-244528:
Old:
```
Configuring this setting for the SSH daemon provides additional
assurance that remote logon via SSH will require a password, even in the event
of misconfiguration elsewhere.

```
New:
```
Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.

```
---
SV-244529:
Old:
```
The use of separate file systems for different paths can protect the
system from failures resulting from a file system becoming full or failing.

```
New:
```
The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.

```
---
SV-244530:
Old:
```
The "nosuid" mount option causes the system not to execute
"setuid" and "setgid" files with owner privileges. This option must be used
for mounting any file system not containing approved "setuid" and "setguid"
files. Executing files from untrusted file systems increases the opportunity
for unprivileged users to attain unauthorized administrative access.

```
New:
```
The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

```
---
SV-244531:
Old:
```
Excessive permissions on local interactive user home directories may
allow unauthorized access to user files by other users.

```
New:
```
Excessive permissions on local interactive user home directories may allow unauthorized access to user files by other users.

```
---
SV-244532:
Old:
```
If a local interactive user's files are group-owned by a group of
which the user is not a member, unintended users may be able to access them.

```
New:
```
If a local interactive user's files are group-owned by a group of which the user is not a member, unintended users may be able to access them.

```
---
SV-244533:
Old:
```
By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account.

    In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to
centralize the configuration of the pam_faillock.so module. Also introduced is
a "local_users_only" option that will only track failed user authentication
attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP,
etc.) users to allow the centralized platform to solely manage user lockout.

    From "faillock.conf" man pages: Note that the default directory that
"pam_faillock" uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the "dir" option.
    The preauth argument must be used when the module is called before the
modules which ask for the user credentials such as the password.

```
New:
```
By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to centralize the configuration of the pam_faillock.so module. Also introduced is a "local_users_only" option that will only track failed user authentication attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP, etc.) users to allow the centralized platform to solely manage user lockout.

From "faillock.conf" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable a different tally directory must be set with the "dir" option.
The preauth argument must be used when the module is called before the modules which ask for the user credentials such as the password.



```
---
SV-244534:
Old:
```
By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account.

    In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to
centralize the configuration of the pam_faillock.so module.  Also introduced is
a "local_users_only" option that will only track failed user authentication
attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP,
etc.) users to allow the centralized platform to solely manage user lockout.

    From "faillock.conf" man pages: Note that the default directory that
"pam_faillock" uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the "dir" option.
    The preauth argument must be used when the module is called before the
modules which ask for the user credentials such as the password.

```
New:
```
By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to centralize the configuration of the pam_faillock.so module.  Also introduced is a "local_users_only" option that will only track failed user authentication attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP, etc.) users to allow the centralized platform to solely manage user lockout.

From "faillock.conf" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable a different tally directory must be set with the "dir" option.
The preauth argument must be used when the module is called before the modules which ask for the user credentials such as the password.



```
---
SV-244535:
Old:
```
A session time-out lock is a temporary action taken when a user stops
work and moves away from the immediate physical vicinity of the information
system but does not log out because of the temporary nature of the absence.
Rather than relying on the user to manually lock their operating system session
prior to vacating the vicinity, operating systems need to be able to identify
when a user's session has idled and take action to initiate the session lock.

    The session lock is implemented at the point where session activity can be
determined and/or controlled.

```
New:
```
A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled.



```
---
SV-244536:
Old:
```
Leaving the user list enabled is a security risk since it allows
anyone with physical access to the system to enumerate known user accounts
without authenticated access to the system.

```
New:
```
Leaving the user list enabled is a security risk since it allows anyone with physical access to the system to enumerate known user accounts without authenticated access to the system.

```
---
SV-244537:
Old:
```
A session lock is a temporary action taken when a user stops work and
moves away from the immediate physical vicinity of the information system but
does not want to log out because of the temporary nature of the absence.
    The session lock is implemented at the point where session activity can be
determined. Rather than be forced to wait for a period of time to expire before
the user session can be locked, RHEL 8 needs to provide users with the ability
to manually invoke a session lock so users can secure their session if it is
necessary to temporarily vacate the immediate physical vicinity.
    Tmux is a terminal multiplexer that enables a number of terminals to be
created, accessed, and controlled from a single screen.  Red Hat endorses tmux
as the recommended session controlling package.

```
New:
```
A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.
The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, RHEL 8 needs to provide users with the ability to manually invoke a session lock so users can secure their session if it is necessary to temporarily vacate the immediate physical vicinity.
Tmux is a terminal multiplexer that enables a number of terminals to be created, accessed, and controlled from a single screen.  Red Hat endorses tmux as the recommended session controlling package.



```
---
SV-244538:
Old:
```
A session time-out lock is a temporary action taken when a user stops
work and moves away from the immediate physical vicinity of the information
system but does not log out because of the temporary nature of the absence.
Rather than relying on the user to manually lock their operating system session
prior to vacating the vicinity, operating systems need to be able to identify
when a user's session has idled and take action to initiate the session lock.

    The session lock is implemented at the point where session activity can be
determined and/or controlled.

    Implementing session settings will have little value if a user is able to
manipulate these settings from the defaults prescribed in the other
requirements of this implementation guide.

    Locking these settings from non-privileged users is crucial to maintaining
a protected baseline.

```
New:
```
A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled.

Implementing session settings will have little value if a user is able to manipulate these settings from the defaults prescribed in the other requirements of this implementation guide.

Locking these settings from non-privileged users is crucial to maintaining a protected baseline.



```
---
SV-244539:
Old:
```
A session time-out lock is a temporary action taken when a user stops
work and moves away from the immediate physical vicinity of the information
system but does not log out because of the temporary nature of the absence.
Rather than relying on the user to manually lock their operating system session
prior to vacating the vicinity, operating systems need to be able to identify
when a user's session has idled and take action to initiate the session lock.

    The session lock is implemented at the point where session activity can be
determined and/or controlled.

    Implementing session settings will have little value if a user is able to
manipulate these settings from the defaults prescribed in the other
requirements of this implementation guide.

    Locking these settings from non-privileged users is crucial to maintaining
a protected baseline.

```
New:
```
A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled.

Implementing session settings will have little value if a user is able to manipulate these settings from the defaults prescribed in the other requirements of this implementation guide.

Locking these settings from non-privileged users is crucial to maintaining a protected baseline.



```
---
SV-244540:
Old:
```
If an account has an empty password, anyone could log on and run
commands with the privileges of that account. Accounts with empty passwords
should never be used in operational environments.

```
New:
```
If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.

```
---
SV-244541:
Old:
```
If an account has an empty password, anyone could log on and run
commands with the privileges of that account. Accounts with empty passwords
should never be used in operational environments.

```
New:
```
If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.

```
---
SV-244542:
Old:
```
Without establishing what type of events occurred, the source of
events, where events occurred, and the outcome of events, it would be difficult
to establish, correlate, and investigate the events leading up to an outage or
attack.

    Audit record content that may be necessary to satisfy this requirement
includes, for example, time stamps, source and destination addresses,
user/process identifiers, event descriptions, success/fail indications,
filenames involved, and access control or flow control rules invoked.

    Associating event types with detected events in RHEL 8 audit logs provides
a means of investigating an attack, recognizing resource utilization or
capacity thresholds, or identifying an improperly configured RHEL 8 system.

```
New:
```
Without establishing what type of events occurred, the source of events, where events occurred, and the outcome of events, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in RHEL 8 audit logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured RHEL 8 system.



```
---
SV-244543:
Old:
```
If security personnel are not notified immediately when storage volume
reaches 75 percent utilization, they are unable to plan for audit record
storage capacity expansion.

```
New:
```
If security personnel are not notified immediately when storage volume reaches 75 percent utilization, they are unable to plan for audit record storage capacity expansion.

```
---
SV-244544:
Old:
```
"Firewalld" provides an easy and effective way to block/limit remote
access to the system via ports, services, and protocols.

    Remote access services, such as those providing remote access to network
devices and information systems, which lack automated control capabilities,
increase risk and make remote user access management difficult at best.

    Remote access is access to DoD nonpublic information systems by an
authorized user (or an information system) communicating through an external,
non-organization-controlled network. Remote access methods include, for
example, dial-up, broadband, and wireless.
    RHEL 8 functionality (e.g., RDP) must be capable of taking enforcement
action if the audit reveals unauthorized activity. Automated control of remote
access sessions allows organizations to ensure ongoing compliance with remote
access policies by enforcing connection rules of remote access applications on
a variety of information system components (e.g., servers, workstations,
notebook computers, smartphones, and tablets).

```
New:
```
"Firewalld" provides an easy and effective way to block/limit remote access to the system via ports, services, and protocols.

Remote access services, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.
RHEL 8 functionality (e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).

```
---
SV-244545:
Old:
```
The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    Utilizing a whitelist provides a configuration management method for
allowing the execution of only authorized software. Using only authorized
software decreases risk by limiting the number of potential vulnerabilities.
Verification of whitelisted software occurs prior to execution or at system
startup.

    User home directories/folders may contain information of a sensitive
nature. Non-privileged users should coordinate any sharing of information with
an SA through shared resources.

    RHEL 8 ships with many optional packages. One such package is a file access
policy daemon called "fapolicyd". "fapolicyd" is a userspace daemon that
determines access rights to files based on attributes of the process and file.
It can be used to either blacklist or whitelist processes or file access.

    Proceed with caution with enforcing the use of this daemon. Improper
configuration may render the system non-functional. The "fapolicyd" API is
not namespace aware and can cause issues when launching or running containers.

```
New:
```
The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

Utilizing a whitelist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities. Verification of whitelisted software occurs prior to execution or at system startup.

User home directories/folders may contain information of a sensitive nature. Non-privileged users should coordinate any sharing of information with an SA through shared resources.

RHEL 8 ships with many optional packages. One such package is a file access policy daemon called "fapolicyd". "fapolicyd" is a userspace daemon that determines access rights to files based on attributes of the process and file. It can be used to either blacklist or whitelist processes or file access.

Proceed with caution with enforcing the use of this daemon. Improper configuration may render the system non-functional. The "fapolicyd" API is not namespace aware and can cause issues when launching or running containers.



```
---
SV-244546:
Old:
```
The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    Utilizing a whitelist provides a configuration management method for
allowing the execution of only authorized software. Using only authorized
software decreases risk by limiting the number of potential vulnerabilities.
Verification of whitelisted software occurs prior to execution or at system
startup.

    User home directories/folders may contain information of a sensitive
nature. Non-privileged users should coordinate any sharing of information with
an SA through shared resources.

    RHEL 8 ships with many optional packages. One such package is a file access
policy daemon called "fapolicyd". "fapolicyd" is a userspace daemon that
determines access rights to files based on attributes of the process and file.
It can be used to either blacklist or whitelist processes or file access.

    Proceed with caution with enforcing the use of this daemon. Improper
configuration may render the system non-functional. The "fapolicyd" API is
not namespace aware and can cause issues when launching or running containers.

```
New:
```
The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

Utilizing a whitelist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities. Verification of whitelisted software occurs prior to execution or at system startup.

User home directories/folders may contain information of a sensitive nature. Non-privileged users should coordinate any sharing of information with an SA through shared resources.

RHEL 8 ships with many optional packages. One such package is a file access policy daemon called "fapolicyd". "fapolicyd" is a userspace daemon that determines access rights to files based on attributes of the process and file. It can be used to either blacklist or whitelist processes or file access.

Proceed with caution with enforcing the use of this daemon. Improper configuration may render the system non-functional. The "fapolicyd" API is not namespace aware and can cause issues when launching or running containers.



```
---
SV-244547:
Old:
```
Without authenticating devices, unidentified or unknown devices may be
introduced, thereby facilitating malicious activity.
    Peripherals include, but are not limited to, such devices as flash drives,
external storage, and printers.
    A new feature that RHEL 8 provides is the USBGuard software framework. The
USBguard-daemon is the main component of the USBGuard software framework. It
runs as a service in the background and enforces the USB device authorization
policy for all USB devices. The policy is defined by a set of rules using a
rule language described in the usbguard-rules.conf file. The policy and the
authorization state of USB devices can be modified during runtime using the
usbguard tool.

    The System Administrator (SA) must work with the site Information System
Security Officer (ISSO) to determine a list of authorized peripherals and
establish rules within the USBGuard software framework to allow only authorized
devices.

```
New:
```
Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.
Peripherals include, but are not limited to, such devices as flash drives, external storage, and printers.
A new feature that RHEL 8 provides is the USBGuard software framework. The USBguard-daemon is the main component of the USBGuard software framework. It runs as a service in the background and enforces the USB device authorization policy for all USB devices. The policy is defined by a set of rules using a rule language described in the usbguard-rules.conf file. The policy and the authorization state of USB devices can be modified during runtime using the usbguard tool.

The System Administrator (SA) must work with the site Information System Security Officer (ISSO) to determine a list of authorized peripherals and establish rules within the USBGuard software framework to allow only authorized devices.

```
---
SV-244548:
Old:
```
Without authenticating devices, unidentified or unknown devices may be
introduced, thereby facilitating malicious activity.

    Peripherals include, but are not limited to, such devices as flash drives,
external storage, and printers.

    A new feature that RHEL 8 provides is the USBGuard software framework. The
USBguard-daemon is the main component of the USBGuard software framework. It
runs as a service in the background and enforces the USB device authorization
policy for all USB devices. The policy is defined by a set of rules using a
rule language described in the usbguard-rules.conf file. The policy and the
authorization state of USB devices can be modified during runtime using the
usbguard tool.

    The System Administrator (SA) must work with the site Information System
Security Officer (ISSO) to determine a list of authorized peripherals and
establish rules within the USBGuard software framework to allow only authorized
devices.

```
New:
```
Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Peripherals include, but are not limited to, such devices as flash drives, external storage, and printers.

A new feature that RHEL 8 provides is the USBGuard software framework. The USBguard-daemon is the main component of the USBGuard software framework. It runs as a service in the background and enforces the USB device authorization policy for all USB devices. The policy is defined by a set of rules using a rule language described in the usbguard-rules.conf file. The policy and the authorization state of USB devices can be modified during runtime using the usbguard tool.

The System Administrator (SA) must work with the site Information System Security Officer (ISSO) to determine a list of authorized peripherals and establish rules within the USBGuard software framework to allow only authorized devices.

```
---
SV-244549:
Old:
```
Without protection of the transmitted information, confidentiality and
integrity may be compromised because unprotected communications can be
intercepted and either read or altered.

    This requirement applies to both internal and external networks and all
types of information system components from which information can be
transmitted (e.g., servers, mobile devices, notebook computers, printers,
copiers, scanners, and facsimile machines). Communication paths outside the
physical protection of a controlled boundary are exposed to the possibility of
interception and modification.

    Protecting the confidentiality and integrity of organizational information
can be accomplished by physical means (e.g., employing physical distribution
systems) or by logical means (e.g., employing cryptographic techniques). If
physical means of protection are employed, then logical means (cryptography) do
not have to be employed, and vice versa.

```
New:
```
Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered. 

This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. 

Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.



```
---
SV-244550:
Old:
```
ICMP redirect messages are used by routers to inform hosts that a more
direct route exists for a particular destination. These messages modify the
host's route table and are unauthenticated. An illicit ICMP redirect message
could result in a man-in-the-middle attack.

```
New:
```
ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-244551:
Old:
```
Source-routed packets allow the source of the packet to suggest that
routers forward the packet along a different path than configured on the
router, which can be used to bypass network security measures. This requirement
applies only to the forwarding of source-routed traffic, such as when
forwarding is enabled and the system is functioning as a router.

```
New:
```
Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when forwarding is enabled and the system is functioning as a router.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-244552:
Old:
```
Source-routed packets allow the source of the packet to suggest that
routers forward the packet along a different path than configured on the
router, which can be used to bypass network security measures. This requirement
applies only to the forwarding of source-routed traffic, such as when
forwarding is enabled and the system is functioning as a router.

```
New:
```
Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when forwarding is enabled and the system is functioning as a router.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-244553:
Old:
```
ICMP redirect messages are used by routers to inform hosts that a more
direct route exists for a particular destination. These messages modify the
host's route table and are unauthenticated. An illicit ICMP redirect message
could result in a man-in-the-middle attack.

```
New:
```
ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-244554:
Old:
```
It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.
    Enabling hardening for the Berkeley Packet Filter (BPF) Just-in-time (JIT)
compiler aids in mitigating JIT spraying attacks.  Setting the value to "2"
enables JIT hardening for all users.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Enabling hardening for the Berkeley Packet Filter (BPF) Just-in-time (JIT) compiler aids in mitigating JIT spraying attacks. Setting the value to "2" enables JIT hardening for all users.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf

```
---
SV-245540:
Old:
```
Adding endpoint security tools can provide the capability to
automatically take actions in response to malicious behavior, which can provide
additional agility in reacting to network threats. These tools also often
include a reporting capability to provide network awareness of the system,
which may not otherwise exist in an organization's systems management regime.

```
New:
```
Adding endpoint security tools can provide the capability to automatically take actions in response to malicious behavior, which can provide additional agility in reacting to network threats. These tools also often include a reporting capability to provide network awareness of the system, which may not otherwise exist in an organization's systems management regime.

```
---
</details>