import asyncio
import json
import logging
import os
import sys
from aiohttp import ClientError
from datetime import date
from uuid import uuid4

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # noqa

from runners.agent_container import (  # noqa:E402
    arg_parser,
    create_agent_with_args,
    AriesAgent,
)
from runners.support.utils import (  # noqa:E402
    check_requires,
    log_msg,
    log_status,
    log_timer,
    prompt,
    prompt_loop,
)

from opa_client.opa import OpaClient
import requests
from jsonsearch import JsonSearch

##  OPA: the following 2 varibles are rego policy and data for OPA
## These should be stored somewhere locally in production.But for testing, I will list them here
test_policy = """

package app.rbac

import future.keywords.contains
import future.keywords.if
import future.keywords.in
import data.test.rbacdata

default allow := false


# Allow the action if the user has the role which is granted permission to perform the action.
allow if {
	some role_name in requested_roles
    input.role == role_name
}

# List all roles with a proper grants for requested service
requested_roles contains role.name if {
    some role in rbacdata.role_grants
    some grant in role.grants
    grant.action == input.action
    grant.object == input.object
}

permission_validator := "role"
"""
data = {
    "role_grants": [
        {
            "name" : "forest worker",
            "grants" : [
                {
                    "action": "execute",
                    "object": "forward"
                },
                {
                    "action": "read",
                    "object": "speed"
                }
            ]
        },
        {
            "name" : "manager",
            "grants" : [
                {
                    "action": "read",
                    "object": "location"
                },
                {
                    "action": "read",
                    "object": "speed"
                }
            ]
        },
        {
            "name" : "repairer",
            "grants" : [
                {
                    "action": "update",
                    "object": "abrasion"
                },
                {
                    "action": "read",
                    "object": "working_hours"
                }
            ]
        }
    ]
}

## Transformation from Permission Validator to VPR
## Transformation from VP to Permission Validator
## !Here is only a test, the function will be loaded from a file in production

##Here begins the explaination of the transformation, the following variable will not be used
permission_validators = ["role"]
vc_schemas_name = ["empolyee schema"]
trusted_issuers = ["BSrNATpiQhguwPvvHKAjbL:3:CL:112:faber.agent.employee_schema"]

# Here is an example Transformation function
transformation = {
    "employee schema": {
        "9ayP8HFT9pefJZZ54tfmoh": [
            {
                "title": "role",
                "role": "title"
            }
        ]
    }
}

service_request_storage = []
agent = None

import random

TAILS_FILE_COUNT = int(os.getenv("TAILS_FILE_COUNT", 100))
CRED_PREVIEW_TYPE = "https://didcomm.org/issue-credential/2.0/credential-preview"
SELF_ATTESTED = os.getenv("SELF_ATTESTED")
TAILS_FILE_COUNT = int(os.getenv("TAILS_FILE_COUNT", 100))

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)


class ForwarderAgent(AriesAgent):
    def __init__(
        self,
        ident: str,
        http_port: int,
        admin_port: int,
        no_auto: bool = False,
        **kwargs,
    ):
        super().__init__(
            ident,
            http_port,
            admin_port,
            prefix="Forwarder",
            no_auto=no_auto,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = None
        self.cred_state = {}
        self.cred_attrs = {}

    async def detect_connection(self):
        await self._connection_ready
        self._connection_ready = None

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()

    async def handle_oob_invitation(self, message):
        pass

    async def handle_connections(self, message):
        print(
            self.ident, "handle_connections", message["state"], message["rfc23_state"]
        )
        conn_id = message["connection_id"]
        if (not self.connection_id) and message["rfc23_state"] == "invitation-sent":
            print(self.ident, "set connection id", conn_id)
            self.connection_id = conn_id
        if (
            message["connection_id"] == self.connection_id
            and message["rfc23_state"] == "completed"
            and (self._connection_ready and not self._connection_ready.done())
        ):
            self.log("Connected")
            self._connection_ready.set_result(True)

    async def handle_issue_credential_v2_0(self, message):
        state = message["state"]
        cred_ex_id = message["cred_ex_id"]
        prev_state = self.cred_state.get(cred_ex_id)
        if prev_state == state:
            return  # ignore
        self.cred_state[cred_ex_id] = state

        self.log(f"Credential: state = {state}, cred_ex_id = {cred_ex_id}")

        if state == "request-received":
            # issue credentials based on offer preview in cred ex record
            if not message.get("auto_issue"):
                await self.admin_POST(
                    f"/issue-credential-2.0/records/{cred_ex_id}/issue",
                    {"comment": f"Issuing credential, exchange {cred_ex_id}"},
                )

    async def handle_issue_credential_v2_0_indy(self, message):
        pass  # employee id schema does not support revocation

    async def handle_present_proof_v2_0(self, message):
        state = message["state"]
        pres_ex_id = message["pres_ex_id"]
        self.log(f"Presentation: state = {state}, pres_ex_id = {pres_ex_id}")

        if state == "presentation-received":
            log_status("#27 Process the proof provided by X")
            log_status("#28 Check if proof is valid")
            proof = await self.admin_POST(
                f"/present-proof-2.0/records/{pres_ex_id}/verify-presentation"
            )
            self.log("Proof = ", proof["verified"])

            # if presentation is a degree schema (proof of education),
            # check values received
            pres_req = message["by_format"]["pres_request"]["indy"]
            pres = message["by_format"]["pres"]["indy"]
            self.log("Presentation = ", pres)
            is_proof_of_role = (
                (pres_req["name"] == "Proof of Role") & (proof["verified"]== "true")
            )
            self.log("is_proof_of_role :", is_proof_of_role)
            if is_proof_of_role:
                log_status("#28.1 Received proof of role, check claims")
                client = OpaClient(
                    host="http://host.docker.internal",
                    port=8181,
                    version="v1"
                )
                requested_object = ""
                requested_action = ""
                for stored_service_request in service_request_storage:
                    try:
                        cur_request = stored_service_request[self.connection_id]
                    except:
                        continue
                    else:
                        requested_object = cur_request["object"]
                        requested_action = cur_request["action"]
                        #TODO delete this object from storage
                request_with_pv = {
                    "input": {
                        "object": requested_object,
                        "action": requested_action
                    }
                }
                for (referent, attr_spec) in pres_req["requested_attributes"].items():
                    # check if the presentation contains the requested attribute or attribute groups
                    is_req_attr_contained = False
                    # Note: response presentation always contains a revealed_attrs key
                    if referent in pres['requested_proof']['revealed_attrs']:
                            is_req_attr_contained = True
                    else:
                        # try to find a revealed attribute group that contains referant
                        try:
                            if referent in pres['requested_proof']['revealed_attr_groups']:
                                is_req_attr_contained = True
                        except:
                            self.log("No attributes are revealed")

                    self.log("Is requested attributes contained", is_req_attr_contained)        
                    if is_req_attr_contained:
                        # Transform the key name in response into the permission validator name
                        jsondata = JsonSearch(object=transformation, mode='j')
                        try:
                            # The request requests attributes
                            rsp_attr_name = attr_spec['name']
                        except:
                            # "name" and "names" will not be contained in the same object in request
                            # The request requests attributes group
                            for rsp_group_attr_name in attr_spec['names']:
                                permission_validator_name = jsondata.search_first_value(key=rsp_group_attr_name)
                                self.log("The revealed attribute group object:",pres['requested_proof']['revealed_attr_groups'][referent])
                                self.log(pres['requested_proof']['revealed_attr_groups'][referent]['values'],rsp_group_attr_name)
                                self.log(pres['requested_proof']['revealed_attr_groups'][referent]['values'][rsp_group_attr_name])
                                request_with_pv["input"][permission_validator_name] = pres['requested_proof']['revealed_attr_groups'][referent]['values'][rsp_group_attr_name]['raw']
                                self.log(
                                    f"{permission_validator_name}: "
                                    f"{pres['requested_proof']['revealed_attr_groups'][referent]['values'][rsp_group_attr_name]['raw']}"
                                )
                        else:
                            permission_validator_name = jsondata.search_first_value(key=rsp_attr_name)
                            request_with_pv["input"][permission_validator_name] = pres['requested_proof']['revealed_attrs'][referent]['raw']
                            self.log(
                                f"{permission_validator_name}: "
                                f"{pres['requested_proof']['revealed_attrs'][referent]['raw']}"
                            )
                    else:
                        self.log(
                            f"{referent}: "
                            "(attribute or attributes group not revealed)"
                        )
                for id_spec in pres["identifiers"]:
                    # just print out the schema/cred def id's of presented claims
                    self.log(f"schema_id: {id_spec['schema_id']}")
                    self.log(f"cred_def_id {id_spec['cred_def_id']}")
                # Evaluate the result with OPA
                log_status("#29 Redirect the request to OPA" )
                self.log("Input of OPA:" ,request_with_pv )
                rsp = client.check_permission(input_data=request_with_pv, policy_name="rbac", rule_name="allow")
                self.log("The result from OPA: ",rsp["result"] )
                if rsp["result"] == True:
                    log_status("#30 The service requester has access to the requested service" )
                else:
                    log_status("#30 Access denied" )
                del client
            else:
                if proof["verified"] == "false":
                    log_status("#28 Validation of VP failed " )
                # in case there are any other kinds of proofs received
                log_status("#28.1 Received ", pres_req["name"])
                

    async def handle_basicmessages(self, message):
        log_status("-"*60)
        try:
            json_service_request = json.loads(message["content"])
            msg_type = json_service_request['message_type']
            requested_object = json_service_request['object']
            requested_action = json_service_request['action']
            connection_id = json_service_request['connection_id']
        except:
            self.log("Received message:", message["content"])
        else:
            if(msg_type != 'service_request'):
                self.log("Received Request:", message["content"])
            else:
                log_status("#21 Receive Service Request")
                self.log("Received Service Request:", message["content"])
                log_status("#22 Fetch requested information from opa")
                client = OpaClient(
                    host="http://host.docker.internal",
                    port=8181,
                    version="v1"
                )
                self.log("Are you running OPA?:",client.check_connection()) # response is  Yes I'm here :)
                policies_list = client.get_policies_list()
                self.log("All OPA policy lists:",policies_list)
                if policies_list == []:
                    self.log("Successfully add data:",client.update_or_create_opa_data(data, "test/rbacdata"))
                    self.log("Successfully add rego policy:",client.update_opa_policy_fromstring(test_policy, "rbac"))
                else:
                    self.log("OPA already have loaded data und policy")
                
                #get the url of the given policy
                info_list = client.get_policies_info()
                url = info_list['rbac']['path'][0]
                get_requested_pv = {
                    "input": {
                        "object": requested_object,
                        "action": requested_action
                    }
                }
                rsp = requests.post(url, json=get_requested_pv)
                rsp_str = str(rsp.content, encoding = "utf-8")
                rsp_decoded = json.loads(rsp_str)
                self.log("Response from OPA", rsp_decoded)
                requested_permission_validators = rsp_decoded['result']['permission_validator']
                self.log("Requested permission validator for the given object and action:",rsp_decoded['result']['requested_roles'])
                # store the request with the connection in storage
                log_status("#23 Generate and send proof request")
                service_request = {self.connection_id: {"object": requested_object,"action": requested_action}}
                service_request_storage.append(service_request)
                self.log("service_request_storage",service_request_storage )
                req_attrs = []
                req_preds = []
                jsondata = JsonSearch(object=transformation, mode='j')
                all_path = jsondata.search_all_path(key=requested_permission_validators) 
                all_value = jsondata.search_all_value(key=requested_permission_validators)
                for i in range(0,len(all_path)):
                    req_attrs.append({"name":all_value[i],"restrictions": [{"schema_name": all_path[i][0],"issuer_did": all_path[i][1]}]})
                    #req_attrs.append({"name":all_value[i],"restrictions": [{"cred_def_id": all_path[i][1]}]})
                    self.log("Adding requested attributes:",req_attrs)
                #form indy proof request
                indy_proof_request = {
                    "name": "Proof of Role",
                    "version": "1.0",
                    "nonce": str(uuid4().int),
                    "requested_attributes": {
                        f"0_{req_attr['name']}_uuid": req_attr
                        for req_attr in req_attrs
                    },
                    "requested_predicates": {}
                }
                self.log("Generate indy proof",indy_proof_request )
                self.log("connection ID",self.connection_id )
                #form the request
                final_proof_request = {
                    "connection_id": self.connection_id,
                    "presentation_request": {"indy": indy_proof_request},
                }
                self.log("Transformed proof request",final_proof_request )
                await self.admin_POST(
                    "/present-proof-2.0/send-request",
                    final_proof_request
                )
                self.log("Send proof request")
                del client


async def main(args):
    forwarder_agent = await create_agent_with_args(args, ident="forwarder")

    try:
        log_status(
            "#1 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {forwarder_agent.wallet_type})"
                if forwarder_agent.wallet_type
                else ""
            )
        )
        agent = ForwarderAgent(
            "forwarder.agent",
            forwarder_agent.start_port,
            forwarder_agent.start_port + 1,
            genesis_data=forwarder_agent.genesis_txns,
            genesis_txn_list=forwarder_agent.genesis_txn_list,
            no_auto=forwarder_agent.no_auto,
            tails_server_base_url=forwarder_agent.tails_server_base_url,
            timing=forwarder_agent.show_timing,
            multitenant=forwarder_agent.multitenant,
            mediation=forwarder_agent.mediation,
            wallet_type=forwarder_agent.wallet_type,
            seed=forwarder_agent.seed,
        )
        await forwarder_agent.initialize(
            the_agent=agent,
        )


        # generate an invitation for Alice
        await forwarder_agent.generate_invitation(display_qr=True, wait=True)

        options = (
            "    (1) Issue Credential\n"
            "    (2) Send Proof Request\n"
            "    (3) Send Message\n"
            "    (X) Exit?\n"
            "[1/2/3/X]"
        )
        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                client = OpaClient(
                    host="http://host.docker.internal",
                    port=8181,
                    version="v1"
                )
                client.delete_opa_policy("rbac")
                del client
                break

            elif option == "1":
                log_status("#13 Issue credential offer to X")
                agent.cred_attrs[cred_def_id] = {
                    "employee_id": "forwarder0009",
                    "name": "Alice Smith",
                    "date": date.isoformat(date.today()),
                    "position": "manager"
                }
                cred_preview = {
                    "@type": CRED_PREVIEW_TYPE,
                    "attributes": [
                        {"name": n, "value": v}
                        for (n, v) in agent.cred_attrs[cred_def_id].items()
                    ],
                }
                offer_request = {
                    "connection_id": agent.connection_id,
                    "comment": f"Offer on cred def id {cred_def_id}",
                    "credential_preview": cred_preview,
                    "filter": {"indy": {"cred_def_id": cred_def_id}},
                }
                await agent.admin_POST(
                    "/issue-credential-2.0/send-offer", offer_request
                )

            elif option == "2":
                log_status("#20 Request proof of degree from alice")
                req_attrs = [
                    {
                        "name": "name",
                        "restrictions": [{"schema_name": "degree schema"}]
                    },
                    {
                        "name": "date",
                        "restrictions": [{"schema_name": "degree schema"}]
                    },
                    {
                        "name": "degree",
                        "restrictions": [{"schema_name": "degree schema"}]
                    }
                ]
                req_preds = []
                indy_proof_request = {
                    "name": "Proof of Education",
                    "version": "1.0",
                    "nonce": str(uuid4().int),
                    "requested_attributes": {
                        f"0_{req_attr['name']}_uuid": req_attr
                        for req_attr in req_attrs
                    },
                    "requested_predicates": {}
                }
                proof_request_web_request = {
                    "connection_id": agent.connection_id,
                    "presentation_request": {"indy": indy_proof_request},
                }
                # this sends the request to our agent, which forwards it to Alice
                # (based on the connection_id)
                await agent.admin_POST(
                    "/present-proof-2.0/send-request",
                    proof_request_web_request
                )

            elif option == "3":
                msg = await prompt("Enter message: ")
                await agent.admin_POST(
                    f"/connections/{agent.connection_id}/send-message", {"content": msg}
                )

        if forwarder_agent.show_timing:
            timing = await forwarder_agent.agent.fetch_timing()
            if timing:
                for line in forwarder_agent.agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = await forwarder_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    parser = arg_parser(ident="forwarder", port=8040)
    args = parser.parse_args()

    ENABLE_PYDEVD_PYCHARM = os.getenv("ENABLE_PYDEVD_PYCHARM", "").lower()
    ENABLE_PYDEVD_PYCHARM = ENABLE_PYDEVD_PYCHARM and ENABLE_PYDEVD_PYCHARM not in (
        "false",
        "0",
    )
    PYDEVD_PYCHARM_HOST = os.getenv("PYDEVD_PYCHARM_HOST", "localhost")
    PYDEVD_PYCHARM_CONTROLLER_PORT = int(
        os.getenv("PYDEVD_PYCHARM_CONTROLLER_PORT", 5001)
    )

    if ENABLE_PYDEVD_PYCHARM:
        try:
            import pydevd_pycharm

            print(
                "forwarder remote debugging to "
                f"{PYDEVD_PYCHARM_HOST}:{PYDEVD_PYCHARM_CONTROLLER_PORT}"
            )
            pydevd_pycharm.settrace(
                host=PYDEVD_PYCHARM_HOST,
                port=PYDEVD_PYCHARM_CONTROLLER_PORT,
                stdoutToServer=True,
                stderrToServer=True,
                suspend=False,
            )
        except ImportError:
            print("pydevd_pycharm library was not found")

    check_requires(args)

    try:
        asyncio.get_event_loop().run_until_complete(main(args))
    except KeyboardInterrupt:
        os._exit(1)