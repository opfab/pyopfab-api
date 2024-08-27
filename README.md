# pyopfab-api

Experimental python API to access OperatorFabric

Last updated: 27th August 2024

## Initial PoC of python API

Initiate a first approach for implementing a client API for OperatorFabric:

OperatorFabric server used for testing: operator-fabric-getting-started server (branch: `release4.2.0`)
The server should be launched prior to testing and the examples should have been run without errors.

Use Python 3.10 and import the requirements. Best practices as follows for creating a virtual env and apply requirements:

``` Shell
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Then execute the following actions to test opfab.send_card() function in the python interpreter or a testing file:

``` Python
import api
opfab = api.OperatorFabricClient("http://localhost:2002/", "admin", "test", "http://localhost:89/auth/realms/dev/protocol/openid-connect/token")
opfab.send_card()
```

## Compatibility matrix with OperatorFabric core versions

| Current branch/version of python API | Compatible with Opfab core version | Tested with opfab getting started branch or version | Last checked |
| ------------------------------------ | ---------------------------------- | --------------------------------------------------  | ------------ |
| branch: pyopfab-api-003              | 4.2.0.RELEASE                      | branch: release4.2.0                                | 27.08.2024   |

--------------------

## END of FILE

--------------------
