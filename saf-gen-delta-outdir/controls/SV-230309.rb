control 'SV-230309' do
  title 'Local RHEL 8 initialization files must not execute world-writable
programs.'
  desc 'If user start-up files execute world-writable programs, especially in
unprotected directories, they could be maliciously modified to destroy user
files or otherwise compromise the system at the user level. If the system is
compromised at the user level, it is easier to elevate privileges to eventually
compromise the system at the root and network level.'
  desc 'check', 'Verify that local initialization files do not execute world-writable
programs.

    Check the system for world-writable files.

    The following command will discover and print world-writable files. Run it
once for each local partition [PART]:

    $ sudo find [PART] -xdev -type f -perm -0002 -print

    For all files listed, check for their presence in the local initialization
files with the following commands:

    Note: The example will be for a system that is configured to create user
home directories in the "/home" directory.

    $ sudo grep <file> /home/*/.*

    If any local initialization files are found to reference world-writable
files, this is a finding.'
  desc 'fix', 'Set the mode on files being executed by the local initialization files with
the following command:

    $ sudo chmod 0755 <file>'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230309'
  tag rid: 'SV-230309r627750_rule'
  tag stig_id: 'RHEL-08-010660'
  tag fix_id: 'F-32953r567674_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  non_interactive_shells = input('non_interactive_shells')

  if input('disable_slow_controls')
    describe "This control consistently takes a long to run and has been disabled
  using the disable_slow_controls attribute." do
    skip "This control consistently takes a long to run and has been disabled
  using the disable_slow_controls attribute. You must enable this control for a
  full accredidation for production."
  end
  else
    ignore_shells = non_interactive_shells.join('|')

    # Get home directory for users with UID >= 1000 or UID == 0 and support interactive logins.
    dotfiles = Set[]
    u = users.where { !shell.match(ignore_shells) && (uid >= 1000 || uid == 0) }.entries
    # For each user, build and execute a find command that identifies initialization files
    # in a user's home directory.
    u.each do |user|
      dotfiles += command("find #{user.home} -xdev -maxdepth 2 ( -name '.*' ! -name '.bash_history' ) -type f").stdout.split("\n")
    end
    ww_files = command('find / -xdev -perm -002 -type f -exec ls {} \;').stdout.lines

    # To reduce the number of commands ran, we use a pattern file in the grep command below
    # So we don't have too long of a grep command, we chunk the list of ww_files
    # into strings not longer than PATTERN_FILE_MAX_LENGTH
    # Based on MAX_ARG_STRLEN, /usr/include/linux/binfmts.h
    # We cut off 100 to leave room for the rest of the arguments
    PATTERN_FILE_MAX_LENGTH = command('getconf PAGE_SIZE').stdout.to_i * 32 - 100
    ww_chunked = ['']
    ww_files.each do |item|
      item = item.strip
      if item.length + "\n".length > PATTERN_FILE_MAX_LENGTH
        raise 'Single pattern is longer than PATTERN_FILE_MAX_LENGTH'
      end
      if ww_chunked[-1].length + "\n".length + item.length > PATTERN_FILE_MAX_LENGTH
        ww_chunked.append('')
      end
      ww_chunked[-1] += "\n" + item # This will leave an extra newline at the beginning of chunks
    end
    ww_chunked = ww_chunked.map(&:strip) # This gets rid of the beginning newlines
    if ww_chunked[0] == ''
      ww_chunked = [] # If we didn't have any ww_files, this will prevent an empty grep pattern
    end

    # Check each dotfile for existence of each world-writeable file
    findings = Set[]
    dotfiles.each do |dotfile|
      dotfile = dotfile.strip
      ww_chunked.each do |ww_pattern_file|
        count = command("grep -c -f <(echo \"#{ww_pattern_file}\") \"#{dotfile}\"").stdout.strip.to_i
        findings << dotfile if count > 0
      end
    end
    describe 'Local initialization files that are found to reference world-writable files' do
      subject { findings.to_a }
      it { should be_empty }
    end
  end
end
