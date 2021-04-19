# agent-upgrader
This script will perform a staged upgrade of AppControl (Bit9) agents along with the required CC3 check (if you've disabled that check from happening automatically), see below.

```
usage: agent-upgrader.py [-h] [-l] [-p POLICY_ID] [-n [COMPUTER_NAMES [COMPUTER_NAMES ...]]] [-t THREADS] [-a AGENT_VERSION] [-o] [-u] [-c]
                                    [-d]

This script will perform a staged upgrade of AppControl (Bit9) agents based on the parameters you provide. Use -l to list the Bit9 policies. Without the
--upgrade or --check parameters, it will only print out the list of computers.

optional arguments:
  -h, --help            show this help message and exit
  -l, --list-policies   List all policies and their IDs to be used as a paramter (optional)
  -p POLICY_ID, --policy-id POLICY_ID
                        Only process computers in this policy id (optional)
  -n [COMPUTER_NAMES [COMPUTER_NAMES ...]], --computer-names [COMPUTER_NAMES [COMPUTER_NAMES ...]]
                        Space separated list of computers to process (ex: "DOMAIN\COMPUTER1 DOMAIN\COMPUTER2 *SERVER*")
  -t THREADS, --threads THREADS
                        The maximum number of simultaneous threads (agent upgrades/checks) at once.
  -a AGENT_VERSION, --agent-version AGENT_VERSION
                        Filter the list of computers to exclude agents at this version (ex: -a 8.5.*)
  -o, --online          Include only online computers (currently connected to the server).
  -u, --upgrade         Perform the upgrade on the selected systems.
  -c, --check           Perform the consistency check on the selected systems.
  -d, --debug           Include debug output.

```

# Installing 
After installing Python3, Create a virtual environment.
```
python3 -m venv c:\somepath
cd c:\somepath\scripts
c:\somepath\scripts\activate.bat
pip install pywin32
pip install cbapi
```

# API Authentication
VMware Carbon Black AppControl (Bit9) uses a per-user API token for authentication.  This token is available via the web UI, on the Edit Login page at the bottom in the API section.  Once you have the API Token, you have to create a credential file using the commands:
```
cd c:\somepath\scripts
python cbapi-protection configure
```

The "cbapi-protection" script is installed when cbapi is installed by pip.  Running the command creates a credential token in c:\users\<username>\.carbonblack\credentials.protection.  This token is used automatically by calls to the cbapi.

This interactive process also sets the HTTPS address of the APPControl server.

# Cache Consistency Checks

Ideally, you will want to disable the automatic Cache Consistency Check that occurs when Yara rules are updated.  This will allow you to use this script to trigger the Cache Consistency Check on your own terms.

https://community.carbonblack.com/t5/Knowledge-Base/App-Control-Does-updating-the-Rules-Installer-on-the-console/ta-p/96998

# References

* CB Protection Python API	https://cbapi.readthedocs.io/en/latest/protection-api.html
* CB API Python	            https://github.com/carbonblack/cbapi-python
* App Control Rest API	    https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/
