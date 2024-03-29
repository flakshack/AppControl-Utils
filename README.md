# AppControl-Utils for VMware Carbon Black AppControl 

This is a collection of scripts I wrote to help me manage my AppControl (aka Bit9 aka Protection) deployment.
These scripts are not supported by VMware Carbon Black.  I use the scripts, but I cannot say
how they will function in your environment.  Please review the LICENSE.txt file.



## Installing 
After installing Python3, Create a virtual environment.
```
copy files to c:\somepath
cd c:\somepath     
python -m venv venv
.\venv\scripts\activate.bat
.\venv\scripts\pip install pywin32
.\venv\scripts\pip install cbapi
```

## API Authentication
VMware Carbon Black AppControl (Bit9) uses a per-user API token for authentication.  This token is available via the web UI, on the Edit Login page at the bottom in the API section.  Once you have the API Token, you have to create a credential file using the commands:
```
.\venv\scripts\python .\venv\scripts\python\cbapi-protection configure
```

The "cbapi-protection" script is installed when cbapi is installed by pip.  Running the command creates a credential token in c:\users\<username>\.carbonblack\credentials.protection.  This token is used automatically by calls to the cbapi.

This interactive process also sets the HTTPS address of the APPControl server.


## Log Settings
The script pulls the settings for logger from log_settings.json at runtime.  It is currently configured to output
to both the STDOUT and Windows Application Event Log.  Follow the directions in log_settings.json to set the registry key 
permissions required for EventLog access.  Alternately, you can edit the file to remove the windows_eventlog handler,
in which case pywin32 is no longer a requirement.


## agent-upgrader
This script will perform a staged upgrade of AppControl (Bit9) agents along with the required CC3 check (if you've disabled that check from happening automatically), see below.

```
usage: agent-upgrader.py [-h] [-l] [-p POLICY_ID]
                         [-n [COMPUTER_NAMES [COMPUTER_NAMES ...]]]
                         [-t THREADS] [-a AGENT_VERSION] [-o] [-u] [-c] [-v]
                         [-q QUIT_TIME]

This script will perform a staged upgrade of AppControl (Bit9) agents based on
the parameters you provide. Use -l to list the Bit9 policies. Without the
--upgrade or --check parameters, it will only print out the list of computers.

optional arguments:
  -h, --help            show this help message and exit
  -l, --list-policies   List all policies and their IDs to be used as a
                        paramter (optional)
  -p POLICY_ID, --policy-id POLICY_ID
                        Only process computers in this policy id (optional)
  -n [COMPUTER_NAMES [COMPUTER_NAMES ...]], --computer-names [COMPUTER_NAMES [COMPUTER_NAMES ...]]
                        Space separated list of computers to process (ex:
                        "DOMAIN\COMPUTER1 DOMAIN\COMPUTER2 *SERVER*")
  -e [EXCLUDE_COMPUTER_NAMES [EXCLUDE_COMPUTER_NAMES ...]], --exclude-computer-names [EXCLUDE_COMPUTER_NAMES [EXCLUDE_COMPUTER_NAMES ...]]
                        Space separated list of computers to exclude. Example: -e DOMAIN\COMPUTER1 DOMAIN\COMPUTER2 *SERVER*                        
  -t THREADS, --threads THREADS
                        The maximum number of simultaneous threads (agent
                        upgrades/checks) at once.
  -a AGENT_VERSION, --agent-version AGENT_VERSION
                        Filter the list of computers to exclude agents at this
                        version (ex: -a 8.5.*)
  -o, --online          Include only online computers (currently connected to
                        the server).
  -u, --upgrade         Perform the upgrade on the selected systems.
  -c, --check           Perform the consistency check on the selected systems.
  -v, --verbose         Include verbose output.
  -q QUIT_TIME, --quit-time QUIT_TIME
                        Set ISO datetime when script should stop performing
                        new upgrades/checks. example: -q "2021-04-20 06:09:00"


```

### Examples

Use -l to list the available policies
```
.\venv\scripts\python.exe agent-upgrader.py -l

---------------Policies-----------------

1 Default Policy
2 Template Policy
4 Local Approval Policy
5 Disabled
6 Workstations - High Enforcement
```

Run the script with the -p <id> or -n <somename> parameters to see what computers will be affected.

```
.\venv\scripts\python.exe agent-upgrader.py -p 6

2021-04-21 18:01:35,031 - appcontrol-agent-upgrader.py - INFO - Searching for computers with query: ['deleted:false', 'policyId:6']
2021-04-21 18:01:35,127 - appcontrol-agent-upgrader.py - INFO - Items returned: 3

Parameters -c, --check and/or -u, --upgrade not specified. List of computers in query shown below:

MYDOMAIN\WIN10-TEST1
MYDOMAIN\WIN10-TEST2
MYDOMAIN\WIN10-TEST3
```

```
.\venv\scripts\python.exe agent-upgrader.py -n *TEST1* *TEST2*
2021-04-21 18:03:09,016 - appcontrol-agent-upgrader.py - INFO - Searching for computers with query: ['deleted:false', 'name:*TEST1*|*TEST2*']
2021-04-21 18:03:09,149 - appcontrol-agent-upgrader.py - INFO - Items returned: 2

Parameters -c, --check and/or -u, --upgrade not specified. List of computers in query shown below:

MYDOMAIN\WIN10-TEST1
MYDOMAIN\WIN10-TEST2
```

Finally, run the upgrade and(or) check process on the selected computers.  In the example below
we exclude systems that have already been upgraded to 8.5.x and tell the script to stop upgrading (but finish already
running commands) at 10 PM.  It also will process 8 threads simultaneously.

```
.\venv\scripts\python.exe agent-upgrader.py -n *WIN10* -u -c -a 8.5.* -q "2021-04-21 22:00:00" -t 8
```



# Cache Consistency Checks

Ideally, you will want to disable the automatic Cache Consistency Check that occurs when Yara rules are updated.  This will allow you to use this script to trigger the Cache Consistency Check on your own terms.

https://community.carbonblack.com/t5/Knowledge-Base/App-Control-Does-updating-the-Rules-Installer-on-the-console/ta-p/96998

# References

* CB Protection Python API	https://cbapi.readthedocs.io/en/latest/protection-api.html
* CB API Python	            https://github.com/carbonblack/cbapi-python
* App Control Rest API	    https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/
