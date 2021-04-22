#!/usr/bin/env python
"""

appcontrol-agent-upgrader.py:

This script will reach out to the Carbon Black AppControl server and upgrade all
of the agents in a staged manner.


CB Protection Python API	https://cbapi.readthedocs.io/en/latest/protection-api.html
CB API Python	            https://github.com/carbonblack/cbapi-python
App Control Rest API	    https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/

pip install pywin32
pip install cbapi

"""
__author__ = 'scottv@rbh.com (Scott Vintinner)'

import logging.config
import sys
import time
import json
import traceback
import argparse
import cbapi.errors
from datetime import datetime, timezone
from cbapi.protection import CbEnterpriseProtectionAPI, Computer, Policy, Event
from queue import Queue
from threading import Thread, current_thread


# ------------------------------------------------------------------
#   MAIN
# ------------------------------------------------------------------
def main(params):

    # Setup logging
    logger = logging.getLogger("appcontrol-agent-upgrader.py")
    logging.getLogger("cbapi").setLevel(logging.WARNING)        # Hide cbapi debug
    logging.getLogger("urllib3").setLevel(logging.WARNING)      # Hide URLLIB debug

    if params.verbose:
        logger.setLevel(logging.DEBUG)
        logging.getLogger("cbapi").setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
        logging.getLogger("cbapi").setLevel(logging.WARNING)

    try:
        cb = CbEnterpriseProtectionAPI()

        # Call the function to print out the available policy IDs
        if params.list_policies:
            print_policies(cb, logger)
        else:

            # ---- Build the Query--------------
            # The base query excludes computers that have been deleted.
            # Note that each time we call query.where below it adds to the existing query
            query = cb.select(Computer).where("deleted:false")

            # Filter by Computer
            if len(params.computer_names) > 0:
                query = query.where(r"name:" + '|'.join(params.computer_names))
            # Filter by Excluding Computers
            if len(params.exclude_computer_names) > 0:
                query = query.where(r"name!" + '|'.join(params.exclude_computer_names))
            # Filter by Policy
            if params.policy_id != 0:
                query = query.where('policyId:' + str(params.policy_id))
            # Filter by Agent Version
            if params.agent_version:
                query = query.where('agentVersion!' + params.agent_version)
            # Filter by Online/Connected Systems (exclude offline by default)
            if not params.offline:
                query = query.where('connected:True')

            # ---- Run the Query----------------------
            logger.info("Searching for computers with query: " + str(query._query))
            found_items = len(query)
            logger.info("Items returned: " + str(found_items))

            # ---- Process the items------------------
            if found_items > 0:
                if not (params.check or params.upgrade):  # Upgrade or Check not specified in parameters
                    print("\nParameters -c, --check and/or -u, --upgrade not specified. " +
                          "List of computers in query shown below:\n")
                    for result in query:
                        print(result.name)
                else:

                    # We're going to use a Queue and Threads to process all of the found computers.
                    # ---- Create Queue------------------------
                    pending_queue = Queue()
                    for result in query:
                        pending_queue.put_nowait(result)

                    # ---- Create Threads----------------------
                    # Create one thread for each -t setting (default 1)

                    workers = []
                    for i in range(params.threads):
                        worker = Thread(target=process_queue, args=(
                            cb, logger, pending_queue, params))
                        worker.daemon = True
                        worker.start()
                        workers.append(worker)

                    # Wait until all of the items in the queue have been processed
                    # This is a messy alternative to pending_queue.join() that allows for CTRL-C
                    try:
                        while True:
                            all_done = True
                            for worker in workers:
                                if worker.is_alive():
                                    all_done = False
                            if all_done:
                                break
                            time.sleep(1)
                    except KeyboardInterrupt:
                        logger.info("CTRL-C received")

    except cbapi.errors.CredentialError as error:
        logger.error("Error with login credentials: " + str(error))
    except cbapi.errors.ServerError as error:
        logger.error("Server raised an HTTP 5XX error: " + str(error))
    except cbapi.errors.ApiError as error:
        logger.error("General API error: " + str(error))


# ------------------------------------------------------------------
#   PROCESS_QUEUE
# ------------------------------------------------------------------
def process_queue(cb, logger, pending_queue, params):
    # This queue is called by threads from main.  It will pop a computer object
    # off the queue (in a threadsafe manner) and process it (upgrade and check as needed).

    while not pending_queue.empty():
        if params.quit_time and params.quit_time <= datetime.now():
            logger.info("Quit time of " + str(params.quit_time) + " reached.")
            with pending_queue.mutex:
                pending_queue.queue.clear()     # Clear the rest of the items in the queue
            break
        else:
            computer = pending_queue.get()      # get removes the item from the queue

            logger.debug(computer.name + ' starting thread: ' + current_thread().name)
            if params.upgrade:
                perform_upgrade(logger, computer)
            if params.check:
                perform_check(logger, computer, cb)

            logger.info(computer.name + ' finished.  Queue items remaining: ' + str(pending_queue.qsize()))
        pending_queue.task_done()           # signals that we're done with this thread

    logger.debug("Thread completed/queue empty: " + current_thread().name)


# ------------------------------------------------------------------
#   UPGRADE_AGENT
# ------------------------------------------------------------------
def perform_upgrade(logger, computer):

    status = computer.upgradeStatus

    logger.debug(computer.name + ' status: ' + status)
    if status == 'Not requested':        # Agent hasn't been asked to upgrade yet, but upgrade is available and ready
        time.sleep(3)
        # Ask the agent to upgrade
        logger.info(computer.name + ' requesting upgrade...')
        computer.forceUpgrade = True     # Setting to cause upgrade
        computer.save()                  # Save setting

        # Loop until the upgrade has completed.
        while status != 'Up to date':
            upgrade_error_count = computer.upgradeErrorCount
            if upgrade_error_count > 0:
                upgrade_error = computer.upgradeError
                logger.error(computer.name + ' reported an upgrade error: ' + upgrade_error)
                break
            else:
                logger.info(computer.name + ' (waiting 10 seconds) current status: ' + status)
                time.sleep(10)      # Wait for 10 seconds before checking again.
                computer.refresh()
                status = computer.upgradeStatus

    elif status == 'Up to date':
        logger.info(computer.name + " already up to date.")

    logger.info(computer.name + ' upgrade process completed with status: ' + status)
    time.sleep(30)


# ------------------------------------------------------------------
#   PERFORM_CHECK
# ------------------------------------------------------------------
def perform_check(logger, computer, cb):
    logger.info(computer.name + ' Starting Cache Consistency Check.')
    start = datetime.now(timezone.utc)     # Grab current time in UTC (Bit9 stores times in UTC)

    # Trigger a full cache consistency check
    uri = computer.urlobject + '/' + str(computer.id)
    # ccFlags:   0x2000   Yara Classification
    #            0x0004   Approve New Files
    # The goal here is to provide the same type of scan that would occur automatically, except
    # that we've configured our Bit9  cc3_on_yara_rule_change=0
    #
    cb.put_object(uri + '/?changeDiagnostics=true', {"ccLevel": 3, "ccFlags": 0x2004})

    while True:
        # Grab the most recent event to see if the cache check has completed
        event_query = cb.select(Event).where("computerID:" + str(computer.id))
        event_query = event_query.where("subtypeName:Cache check complete")
        event_query = event_query.sort("timestamp DESC").first()

        latest_event = datetime(2020, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc)
        if event_query is not None:  # Try to parse the event's timestamp into a datetime
            latest_event = datetime.strptime(event_query.timestamp, '%Y-%m-%dT%H:%M:%S%z')

        if latest_event > start:    # Compare with our start datetime
            logger.info(computer.name + ' cache check complete.')
            break
        else:
            logger.info(computer.name + ' waiting 60 seconds for "Cache check complete" event (' +
                        str(datetime.now(timezone.utc) - start).split(".")[0] + ')')

            time.sleep(60)  # Wait for 60 seconds before checking again.


# ------------------------------------------------------------------
#   PRINT_POLICIES
# ------------------------------------------------------------------
def print_policies(cb, logger):
    try:
        print('\n---------------Policies-----------------\n')
        query = cb.select(Policy)
        for policy in query:
            print(str(policy.id) + ' ' + policy.name)

        print('\nUse the -p <id of policy> to limit the scope to computers in that policy.\n')

    except cbapi.errors.CredentialError as error:
        logger.error("Error with login credentials: " + str(error))
    except cbapi.errors.ServerError as error:
        logger.error("Server raised an HTTP 5XX error: " + str(error))
    except cbapi.errors.ApiError as error:
        logger.error("General API error: " + str(error))


# ------------------------------------------------------------------
#   LOGGING
# ------------------------------------------------------------------
def initialize_logging():
    try:
        f = open("log_settings.json", 'rt')
        log_config = json.load(f)
        f.close()
        logging.config.dictConfig(log_config)
    except FileNotFoundError:
        print("Log configuration file not found: " + traceback.format_exc())
        logging.basicConfig(level=logging.DEBUG)        # fallback to basic settings
    except json.decoder.JSONDecodeError:
        print("Error parsing logger config file: " + traceback.format_exc())
        raise


# ------------------------------------------------------------------
#   ARGPARSE
# ------------------------------------------------------------------
if __name__ == '__main__':  # This code is executed when the script is run from the command line

    initialize_logging()      # configure logging (from settings.py)

    description = ('\n\nThis script will perform a staged upgrade of AppControl (Bit9) agents based on the ' +
                   'parameters you provide.  Use -l to list the Bit9 policies. ' +
                   'Without the --upgrade or --check parameters, it will only print out the list of computers.\n')

    parser = argparse.ArgumentParser(description=description)  # We're using argparse to grab CLI parameters

    # Add possible CLI parameters
    parser.add_argument("-l", "--list-policies", action="store_true", default=False,
                        help='List all policies and their IDs to be used as a paramter (optional)')
    parser.add_argument("-p", "--policy-id", action="store", default=0, type=int,
                        help='Only process computers in this policy id (optional)')
    parser.add_argument("-n", "--computer-names", action="store", type=str, default=[], nargs='*',
                        help='Space separated list of computers to process. ' +
                             r'Example: -n DOMAIN\COMPUTER1 DOMAIN\COMPUTER2 *SERVER*')
    parser.add_argument("-e", "--exclude-computer-names", action="store", type=str, default=[], nargs='*',
                        help='Space separated list of computers to exclude. ' +
                             r'Example: -e DOMAIN\COMPUTER1 DOMAIN\COMPUTER2 *SERVER*')
    parser.add_argument("-t", "--threads", action="store", default=1, type=int,
                        help='The maximum number of simultaneous threads (agent upgrades/checks) at once.')
    parser.add_argument("-a", "--agent-version", action="store", default='', type=str,
                        help='Filter the list of computers to exclude agents at this version (ex:  -a 8.5.*)')
    parser.add_argument("-o", "--offline", action="store_true", default=False,
                        help='Include offline computers (not currently connected to the server).')
    parser.add_argument("-u", "--upgrade", action="store_true", default=False,
                        help='Perform the upgrade on the selected systems.')
    parser.add_argument("-c", "--check", action="store_true", default=False,
                        help='Perform the consistency check on the selected systems.')
    parser.add_argument("-v", "--verbose", action="store_true", default=False,
                        help='Include verbose output.')
    parser.add_argument("-q", "--quit-time", action="store", type=datetime.fromisoformat,
                        help='Set ISO datetime when script should stop performing new upgrades/checks. '
                             + 'Currently running upgrades/checks will finish as expected. '
                             + 'Example: -q "2021-04-20 06:09:00"')

    # Set the default argument
    args = parser.parse_args()

    # Call the main function
    sys.exit(main(args))
