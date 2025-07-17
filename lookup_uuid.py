# This program looks up a system hostname, then connects to Tenable Vulnerability Management (TVM) and looks for a matching agent UUID.
# If it finds one or more matches, it prints the agent UUID and the first seen date.
# Populate /etc/tenable_tag or HKLM\Tenable\TAG with the value with the earliest date to prevent duplicates in TVM when rebuilding a system.

# This code is presented for example purposes and is unsupported.

from tenable.io import TenableIO
import socket
import getpass

# get API keys from user (this prevents secrets from ending up in command history or worse yet, being hardcoded)
accesskey = getpass.getpass(prompt='Enter your access key for TVM: ')
secretkey = getpass.getpass(prompt='Enter your secret key for TVM: ')

# Initialize Tenable Vulnerability Management
tvm = TenableIO(accesskey, secretkey)

# get list of licensed assets
assets = tvm.exports.assets(is_licensed=True, chunk_size=1000) # chunk_size is configurable, it's always a tradeoff. Tenable does not recommend setting this higher than 5000.

# look for a match. the fields we want are agent_names and agent_uuid.
hostname = socket.gethostname() # get hostname of localhost
matches = 0 # no match
for asset in assets:
    try:
        if asset['agent_names'][0] == hostname:
            print('Found match. Update HKLM\Software\Tenable\TAG or /etc/tenable_tag:')
            print(asset['agent_uuid'], 'First seen:', asset['first_seen'])
            matches += 1 # update if we found a match
    except:
        pass
if matches == 0:
    print('No match.')
if matches > 1:
    print('Multiple matches. Recommend you use the one with the earliest first seen date and delete newer ones.')
# fields: agent_uuid, hostnames, agent_names
