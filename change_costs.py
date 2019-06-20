#!/usr/bin/env python
import sys
import os
import argparse
from copy import deepcopy
import csv

####
#
# Enter other desired optional system modules here.
#
####

import json

####
#
# End other desired system modules.
#
####

# Import CloudGenix Python SDK
try:
    import cloudgenix
    jdout = cloudgenix.jdout
    jd = cloudgenix.jd
except ImportError as e:
    cloudgenix = None
    sys.stderr.write("ERROR: 'cloudgenix' python module required. (try 'pip install cloudgenix').\n {0}\n".format(e))
    sys.exit(1)

# Import Progressbar2
try:
    from progressbar import Bar, ETA, Percentage, ProgressBar
except ImportError as e:
    Bar = None
    ETA = None
    Percentage = None
    ProgressBar = None
    sys.stderr.write("ERROR: 'progressbar2' python module required. (try 'pip install progressbar2').\n {0}\n".format(e))
    sys.exit(1)

# Import tabulate
try:
    from tabulate import tabulate
except ImportError as e:
    tabulate = None
    sys.stderr.write("ERROR: 'tabulate' python module required. (try 'pip install tabulate').\n {0}\n".format(e))
    sys.exit(1)


# Check for cloudgenix_settings.py config file in cwd.
sys.path.append(os.getcwd())
try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # if cloudgenix_settings.py file does not exist,
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

try:
    # Also, seperately try and import USERNAME/PASSWORD from the config file.
    from cloudgenix_settings import CLOUDGENIX_USER, CLOUDGENIX_PASSWORD

except ImportError:
    # will get caught below
    CLOUDGENIX_USER = None
    CLOUDGENIX_PASSWORD = None


# Handle differences between python 2 and 3. Code can use text_type and binary_type instead of str/bytes/unicode etc.
if sys.version_info < (3,):
    text_type = unicode
    binary_type = str
else:
    text_type = str
    binary_type = bytes


####
#
# Start custom modifiable code
#
####

GLOBAL_MY_SCRIPT_NAME = "WAN Interface Cost set by Circuit Catagory (waninterfacelabel)"
GLOBAL_MY_SCRIPT_VERSION = "v1.0"


class CloudGenixWICostError(Exception):
    """
    Custom exception for errors, allows errors to be caught if using as function instead of script.
    """
    pass


def throw_error(message, resp=None, cr=True):
    """
    Non-recoverable error, write message to STDERR and exit or raise exception
    :param message: Message text
    :param resp: Optional - CloudGenix SDK Response object
    :param cr: Optional - Use (or not) Carriage Returns.
    :return: No Return, throws exception.
    """
    output = "ERROR: " + str(message)
    if cr:
        output += "\n"
    sys.stderr.write(output)
    if resp is not None:
        output2 = str(jdout_detailed(resp))
        if cr:
            output2 += "\n"
        sys.stderr.write(output2)
    raise CloudGenixWICostError(message)


def throw_warning(message, resp=None, cr=True):
    """
    Recoverable Warning.
    :param message: Message text
    :param resp: Optional - CloudGenix SDK Response object
    :param cr: Optional - Use (or not) Carriage Returns.
    :return: None
    """
    output = "WARNING: " + str(message)
    if cr:
        output += "\n"
    sys.stderr.write(output)
    if resp is not None:
        output2 = str(cloudgenix.jdout_detailed(resp))
        if cr:
            output2 += "\n"
        sys.stderr.write(output2)
    return


def extract_items(resp_object, error_label=None):
    """
    Extract
    :param resp_object: CloudGenix Extended Requests.Response object.
    :param error_label: Optional text to describe operation on error.
    :return: list of 'items' objects
    """
    items = resp_object.cgx_content.get('items')

    if resp_object.cgx_status and isinstance(items, list):

        # return data
        return items

    # handle 404 for certian APIs where objects may not exist
    elif resp_object.status_code in [404]:
        return []

    else:
        if error_label is not None:
            throw_error("Unable to cache {0}.".format(error_label), resp_object)
            return []
        else:
            throw_error("Unable to cache response.".format(error_label), resp_object)
            return []


def update_costs(sdk, cost_val, circuitcategory_val, simulate_val, output):

    if simulate_val:
        output_results = [["Site", "WAN Network", "Circuit Category", "WAN Interface", "Previous Cost",
                           "Simulated Cost"]]
    else:
        output_results = [["Site", "WAN Network", "Circuit Category", "WAN Interface", "Previous Cost",
                           "Changed Cost"]]

    circuitcategories_list = extract_items(sdk.get.waninterfacelabels(), 'circuitcategories')
    circuitcategories_id2n = {text_type(i.get('id')): i.get('name') for i in circuitcategories_list}
    circuitcategories_n2id = {text_type(i.get('name')): i.get('id') for i in circuitcategories_list}

    cat_id = circuitcategories_n2id.get(circuitcategory_val)
    if not cat_id:
        throw_error("Category {0} not found. Valid Categories: {1}".format(circuitcategory_val,
                                                                           ", ".join(circuitcategories_n2id.keys())))

    wannetworks_list = extract_items(sdk.get.wannetworks(), 'wannetworks')
    wannetworks_id2n = {text_type(i.get('id')): i.get('name') for i in list(wannetworks_list)}
    sites_list = extract_items(sdk.get.sites(), 'sites')
    sites_id2n = {text_type(i.get('id')): i.get('name') for i in list(sites_list)}

    # Great, now we have max objects that can be queried. Set status bar
    firstbar = len(sites_list) + 1
    barcount = 1

    print("Working through all sites..")

    # could be a long query - start a progress bar.
    pbar = ProgressBar(widgets=[Percentage(), Bar(), ETA()], max_value=firstbar).start()

    for site in sites_list:
        site_id = site.get('id')
        site_name = site.get('name')
        waninterfaces_list = extract_items(sdk.get.waninterfaces(site_id), 'waninterfaces')
        for waninterface in waninterfaces_list:

            network_id = waninterface.get('network_id')
            network_name = wannetworks_id2n.get(network_id, network_id)
            swi_name = waninterface.get('name')
            if swi_name is None:
                swi_name = "Circuit to {0}".format(network_name)
            swi_category = waninterface.get('label_id')
            swi_id = waninterface.get('id')
            prev_cost = waninterface.get('cost')

            # check if match.
            if cat_id == swi_category:
                # Match!

                if simulate_val:
                    # simulate, just add column.
                    output_results.append([site_name, network_name,
                                           circuitcategories_id2n.get(swi_category, swi_category),
                                           swi_name,
                                           prev_cost,
                                           cost_val])
                else:
                    # make changes.
                    swi_template = deepcopy(waninterface)
                    swi_template['cost'] = cost_val
                    resp = sdk.put.waninterfaces(site_id, swi_id, swi_template)
                    if not resp.cgx_status:
                        throw_warning("Set WAN Interface cost failed: ", resp)
                        output_results.append([site_name, network_name,
                                               circuitcategories_n2id.get(swi_category, swi_category),
                                               swi_name,
                                               prev_cost,
                                               prev_cost])
                    else:
                        output_results.append([site_name, network_name,
                                               circuitcategories_n2id.get(swi_category, swi_category),
                                               swi_name,
                                               prev_cost,
                                               cost_val])
        # finished this site_id, next.
        barcount += 1
        pbar.update(barcount)

    # finish after iteration.
    pbar.finish()

    # was output to file specified?
    if output is None:
        # print
        print(tabulate(output_results, headers="firstrow", tablefmt="simple"))
    else:
        with open(output, "w") as csv_output:
            writer = csv.writer(csv_output, quoting=csv.QUOTE_ALL)
            writer.writerows(output_results)

####
#
# End custom modifiable code
#
####


# Start the script.
def go():
    """
    Stub script entry point. Authenticates CloudGenix SDK, and gathers options from command line to run do_site()
    :return: No return
    """

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0} ({1})".format(GLOBAL_MY_SCRIPT_NAME, GLOBAL_MY_SCRIPT_VERSION))

    ####
    #
    # Add custom cmdline argparse arguments here
    #
    ####

    custom_group = parser.add_argument_group('custom_args', 'Circuit matching arguments')
    custom_group.add_argument("--cost", help="Cost to set the Wan Interfaces to (0-255)",
                              required=True, type=int)
    custom_group.add_argument("--category", help="Circuit Category (waninterface label) name to match for change.",
                              required=True, type=text_type)
    custom_group.add_argument("--simulate", help="Simulate changes (don't actually make any changes.)",
                              action='store_true',
                              default=False)
    custom_group.add_argument('--output', type=text_type, default=None,
                              help="Output to filename. If not specified, will print output on STDOUT.")

    ####
    #
    # End custom cmdline arguments
    #
    ####

    # Standard CloudGenix script switches.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. https://api.elcapitan.cloudgenix.com",
                                  default=None)

    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of cloudgenix_settings.py "
                                                   "or prompting",
                             default=None)
    login_group.add_argument("--password", "-PW", help="Use this Password instead of cloudgenix_settings.py "
                                                       "or prompting",
                             default=None)
    login_group.add_argument("--insecure", "-I", help="Do not verify SSL certificate",
                             action='store_true',
                             default=False)
    login_group.add_argument("--noregion", "-NR", help="Ignore Region-based redirection.",
                             dest='ignore_region', action='store_true', default=False)

    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--sdkdebug", "-D", help="Enable SDK Debug output, levels 0-2", type=int,
                             default=0)

    args = vars(parser.parse_args())

    sdk_debuglevel = args["sdkdebug"]

    # Build SDK Constructor
    if args['controller'] and args['insecure']:
        sdk = cloudgenix.API(controller=args['controller'], ssl_verify=False)
    elif args['controller']:
        sdk = cloudgenix.API(controller=args['controller'])
    elif args['insecure']:
        sdk = cloudgenix.API(ssl_verify=False)
    else:
        sdk = cloudgenix.API()

    # check for region ignore
    if args['ignore_region']:
        sdk.ignore_region = True

    # SDK debug, default = 0
    # 0 = logger handlers removed, critical only
    # 1 = logger info messages
    # 2 = logger debug messages.

    if sdk_debuglevel == 1:
        # CG SDK info
        sdk.set_debug(1)
    elif sdk_debuglevel >= 2:
        # CG SDK debug
        sdk.set_debug(2)

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # figure out user
    if args["email"]:
        user_email = args["email"]
    elif CLOUDGENIX_USER:
        user_email = CLOUDGENIX_USER
    else:
        user_email = None

    # figure out password
    if args["password"]:
        user_password = args["password"]
    elif CLOUDGENIX_PASSWORD:
        user_password = CLOUDGENIX_PASSWORD
    else:
        user_password = None

    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["password"]:
        sdk.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if sdk.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit(1)

    else:
        while sdk.tenant_id is None:
            sdk.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not sdk.tenant_id:
                user_email = None
                user_password = None

    ####
    #
    # Do your custom work here, or call custom functions.
    #
    ####

    result =  update_costs(sdk, args['cost'], args['category'], args['simulate'], args['output'])

    ####
    #
    # End custom work.
    #
    ####


if __name__ == "__main__":
    go()
