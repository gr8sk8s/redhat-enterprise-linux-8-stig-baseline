control 'SV-251707' do
  title 'RHEL 8 library directories must have mode 755 or less permissive.'
  desc 'If RHEL 8 were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to RHEL 8 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals will be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the system-wide shared library directories within "/lib", "/lib64", "/usr/lib" and "/usr/lib64" have mode "755" or less permissive with the following command:

$ sudo find /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type d -exec stat -c "%n %a" '{}' \;

If any system-wide shared library directories are found to be group-writable or world-writable, this is a finding.)
  desc 'fix', 'Configure the library directories to be protected from unauthorized access. Run the following command, replacing "[DIRECTORY]" with any library directory with a mode more permissive than 755.

$ sudo chmod 755 [DIRECTORY]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-55144r809343_chk'
  tag severity: 'medium'
  tag gid: 'V-251707'
  tag rid: 'SV-251707r809345_rule'
  tag stig_id: 'RHEL-08-010331'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-55098r809344_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
