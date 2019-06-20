# cloudgenix_waninterface_cost
Quick script to change all circuits that are part of a Circuit Category to a new cost using CloudGenix Python SDK

#### Files
* `change_costs.py` - Script to modify WAN Interface Costs
* `cloudgenix_settings.py.example` - example of a cloudgenix_settings.py authentication file.

#### Authentication
the `change_costs.py` looks for the following for AUTH, in this order of precedence:
1. `--email` or `--password` options on the command line.
2. CLOUDGENIX_USER and CLOUDGENIX_PASSWORD values imported from `cloudgenix_settings.py`
3. CLOUDGENIX_AUTH_TOKEN value imported from `cloudgenix_settings.py`
4. X_AUTH_TOKEN environment variable
5. AUTH_TOKEN environment variable
6. Interactive prompt for user/pass (if one is set, or all other methods fail.) 

#### Arguments
```
usage: change_costs.py [-h] --cost COST --category CATEGORY [--simulate]
                       [--output OUTPUT] [--controller CONTROLLER]
                       [--email EMAIL] [--password PASSWORD] [--insecure]
                       [--noregion] [--sdkdebug SDKDEBUG]

WAN Interface Cost set by Circuit Catagory (waninterfacelabel) (v1.0)

optional arguments:
  -h, --help            show this help message and exit

custom_args:
  Circuit matching arguments

  --cost COST           Cost to set the Wan Interfaces to (0-255)
  --category CATEGORY   Circuit Category (waninterface label) name to match
                        for change.
  --simulate            Simulate changes (don't actually make any changes.)
  --output OUTPUT       Output to filename. If not specified, will print
                        output on STDOUT.

API:
  These options change how this program connects to the API.

  --controller CONTROLLER, -C CONTROLLER
                        Controller URI, ex.
                        https://api.elcapitan.cloudgenix.com

Login:
  These options allow skipping of interactive login

  --email EMAIL, -E EMAIL
                        Use this email as User Name instead of
                        cloudgenix_settings.py or prompting
  --password PASSWORD, -PW PASSWORD
                        Use this Password instead of cloudgenix_settings.py or
                        prompting
  --insecure, -I        Do not verify SSL certificate
  --noregion, -NR       Ignore Region-based redirection.

Debug:
  These options enable debugging output

  --sdkdebug SDKDEBUG, -D SDKDEBUG
                        Enable SDK Debug output, levels 0-2
```

