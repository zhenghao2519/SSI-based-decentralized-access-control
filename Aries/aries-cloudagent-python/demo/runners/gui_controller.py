import asyncio
import json
import logging
import os
import sys
import yaml
import indy
from aiohttp import ClientError
from datetime import date
from uuid import uuid4

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # noqa

from runners.agent_container import (  # noqa:E402
    arg_parser,
    create_agent_with_args,
    AriesAgent,
    AgentContainer
)
from runners.support.utils import (  # noqa:E402
    check_requires,
    log_msg,
    log_status,
    log_timer,
    prompt,
    prompt_loop,
)
from runners.support.agent import (  # noqa:E402
    DemoAgent,
    default_genesis_txns,
    start_mediator_agent,
    connect_wallet_to_mediator,
    start_endorser_agent,
    connect_wallet_to_endorser,
    CRED_FORMAT_INDY,
    CRED_FORMAT_JSON_LD,
    DID_METHOD_KEY,
    KEY_TYPE_BLS,
)

from aiohttp import (
    web,
    ClientSession,
    ClientRequest,
    ClientResponse,
    ClientError,
    ClientTimeout,
)
from opa_client.opa import OpaClient
import requests
from jsonsearch import JsonSearch
import sys
import time

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

# for evaluation
total_verification_time = 0
total_creation_time = 0
total_transformation_time = 0


class GuiAgent(AriesAgent):
    def __init__(
            self,
            ident: str,
            http_port: int,
            admin_port: int,
            no_auto: bool = False,
            opa_address: str = None,
            opa_port: str = None,
            acm: str = None,
            transformation: str = None,
            sock=None,
            **kwargs,
    ):
        super().__init__(
            ident,
            http_port,
            admin_port,
            prefix="Gui",
            no_auto=no_auto,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = None
        self.cred_state = {}
        self.cred_attrs = {}
        self.opa_address = opa_address
        self.opa_port = opa_port
        self.transformation = transformation
        self.sock = sock
        self.acm = acm

    async def detect_connection(self):
        await self._connection_ready
        self._connection_ready = None

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()

    async def handle_oob_invitation(self, message):
        pass

    async def handle_connections(self, message):
        log_status(
            self.ident + "handle_connections" + message["state"] + message["rfc23_state"]
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

    # async def handle_issue_credential_v2_0(self, message):
    #     state = message["state"]
    #     cred_ex_id = message["cred_ex_id"]
    #     prev_state = self.cred_state.get(cred_ex_id)
    #     if prev_state == state:
    #         return  # ignore
    #     self.cred_state[cred_ex_id] = state
    #
    #     self.log(f"Credential: state = {state}, cred_ex_id = {cred_ex_id}")
    #
    #     if state == "request-received":
    #         # issue credentials based on offer preview in cred ex record
    #         if not message.get("auto_issue"):
    #             await self.admin_POST(
    #                 f"/issue-credential-2.0/records/{cred_ex_id}/issue",
    #                 {"comment": f"Issuing credential, exchange {cred_ex_id}"},
    #             )
    #
    # async def handle_issue_credential_v2_0_indy(self, message):
    #     pass  # employee id schema does not support revocation

    async def handle_present_proof_v2_0(self, message):

        global total_verification_time
        global total_creation_time
        global total_transformation_time
        state = message["state"]
        # for 49 bytes in an empty string
        base64_data_size = 0
        try:
            base64_data_size += (
                        sys.getsizeof(json.dumps(message["pres_request"]["request_presentations~attach"])) - 49)
        except:
            pass

        try:
            base64_data_size += (sys.getsizeof(json.dumps(message["pres"]["presentations~attach"])) - 49)
        except:
            pass
        log_status("base64 size" + str(base64_data_size))
        log_status(
            f"Presentation: state = {state}, size:" + str(sys.getsizeof(json.dumps(message)) - 49 - base64_data_size))
        pres_ex_id = message["pres_ex_id"]
        self.log(f"Presentation: state = {state}, pres_ex_id = {pres_ex_id}")
        if state == "request-received":
            # prover role
            log_status(
                "#24 Query for credentials in the wallet that satisfy the proof request"
            )
            pres_request_indy = message["by_format"].get("pres_request", {}).get("indy")
            pres_request_dif = message["by_format"].get("pres_request", {}).get("dif")
            request = {}

            if not pres_request_dif and not pres_request_indy:
                raise Exception("Invalid presentation request received")

            if pres_request_indy:
                # include self-attested attributes (not included in credentials)
                creds_by_reft = {}
                revealed = {}
                self_attested = {}
                predicates = {}

                try:
                    # select credentials to provide for the proof
                    creds = await self.admin_GET(
                        f"/present-proof-2.0/records/{pres_ex_id}/credentials"
                    )
                    if creds:
                        # select only indy credentials
                        creds = [x for x in creds if "cred_info" in x]
                        if "timestamp" in creds[0]["cred_info"]["attrs"]:
                            sorted_creds = sorted(
                                creds,
                                key=lambda c: int(c["cred_info"]["attrs"]["timestamp"]),
                                reverse=True,
                            )
                        else:
                            sorted_creds = creds
                        for row in sorted_creds:
                            for referent in row["presentation_referents"]:
                                if referent not in creds_by_reft:
                                    creds_by_reft[referent] = row

                    # submit the proof wit one unrevealed revealed attribute
                    revealed_flag = True
                    for referent in pres_request_indy["requested_attributes"]:
                        if referent in creds_by_reft:
                            revealed[referent] = {
                                "cred_id": creds_by_reft[referent]["cred_info"][
                                    "referent"
                                ],
                                "revealed": True,
                            }
                            revealed_flag = True
                        else:
                            self_attested[referent] = "my self-attested value"

                    for referent in pres_request_indy["requested_predicates"]:
                        if referent in creds_by_reft:
                            predicates[referent] = {
                                "cred_id": creds_by_reft[referent]["cred_info"][
                                    "referent"
                                ]
                            }

                    log_status("#25 Generate the indy proof")
                    indy_request = {
                        "indy": {
                            "requested_predicates": predicates,
                            "requested_attributes": revealed,
                            "self_attested_attributes": self_attested,
                        }
                    }
                    request.update(indy_request)
                except ClientError:
                    pass

            if pres_request_dif:
                try:
                    # select credentials to provide for the proof
                    creds = await self.admin_GET(
                        f"/present-proof-2.0/records/{pres_ex_id}/credentials"
                    )
                    if creds and 0 < len(creds):
                        # select only dif credentials
                        creds = [x for x in creds if "issuanceDate" in x]
                        creds = sorted(
                            creds,
                            key=lambda c: c["issuanceDate"],
                            reverse=True,
                        )
                        records = creds
                    else:
                        records = []

                    log_status("#25 Generate the dif proof")
                    dif_request = {
                        "dif": {},
                    }
                    # specify the record id for each input_descriptor id:
                    dif_request["dif"]["record_ids"] = {}
                    for input_descriptor in pres_request_dif["presentation_definition"][
                        "input_descriptors"
                    ]:
                        input_descriptor_schema_uri = []
                        for element in input_descriptor["schema"]:
                            input_descriptor_schema_uri.append(element["uri"])

                        for record in records:
                            if self.check_input_descriptor_record_id(
                                    input_descriptor_schema_uri, record
                            ):
                                record_id = record["record_id"]
                                dif_request["dif"]["record_ids"][
                                    input_descriptor["id"]
                                ] = [
                                    record_id,
                                ]
                                break
                    # log_msg("presenting ld-presentation:", dif_request)
                    request.update(dif_request)

                    # NOTE that the holder/prover can also/or specify constraints by including the whole proof request
                    # and constraining the presented credentials by adding filters, for example:
                    #
                    # request = {
                    #     "dif": pres_request_dif,
                    # }
                    # request["dif"]["presentation_definition"]["input_descriptors"]["constraints"]["fields"].append(
                    #      {
                    #          "path": [
                    #              "$.id"
                    #          ],
                    #          "purpose": "Specify the id of the credential to present",
                    #          "filter": {
                    #              "const": "https://credential.example.com/residents/1234567890"
                    #          }
                    #      }
                    # )
                    #
                    # (NOTE the above assumes the credential contains an "id", which is an optional field)

                except ClientError:
                    pass

            log_status("Generated proof: " + json.dumps(request))
            log_status("#26 Send the proof to X: ")
            start_time = time.process_time()
            await self.admin_POST(
                f"/present-proof-2.0/records/{pres_ex_id}/send-presentation",
                request,
            )
            end_time = time.process_time()
            #log_status('TIME generate proof in ms in flow 2: ' + str((end_time - start_time) * 1000))
            total_creation_time += (end_time - start_time) * 1000
            #log_status('TIME total_creation_time in ms in flow 2: ' + str(total_creation_time))
            # msg = await prompt("Do you want to reveal these data? (Y/n): ")
            # send_proof = False
            # if(msg == 'Y'):
            #     send_proof = True
            # elif msg == "n" :
            #     send_proof = False
            # else:
            #     self.log("Invalid input, process abonden")
            # if send_proof:
            #     log_status("#26 Send the proof to X: " )
            #     await self.admin_POST(
            #         f"/present-proof-2.0/records/{pres_ex_id}/send-presentation",
            #         request,
            #     )
            # else:
            #     log_status("#26 Process abonden" )
            #     await self.admin_DELETE(
            #         f"/present-proof-2.0/records/{pres_ex_id}"
            #     )
        if state == "presentation-received":
            log_status("#27 Process the proof provided by X")
            log_status("#28 Check if proof is valid")
            start_time = time.process_time()
            proof = await self.admin_POST(
                f"/present-proof-2.0/records/{pres_ex_id}/verify-presentation"
            )
            end_time = time.process_time()
            #log_status('TIME verify presentation in ms in flow 2: ' + str((end_time - start_time) * 1000))
            total_verification_time += (end_time - start_time) * 1000
            self.log("Proof = ", proof["verified"])

            # if presentation is a degree schema (proof of education),
            # check values received
            pres_req = message["by_format"]["pres_request"]["indy"]
            pres = message["by_format"]["pres"]["indy"]
            # self.log("Presentation = ", pres)
            is_proof_of_servive_request = (
                    (pres_req["name"] == "Proof of Service Request") & (proof["verified"] == "true")
            )
            # self.log("is_proof_of_servive_request :", is_proof_of_servive_request)
            if is_proof_of_servive_request:
                log_status("#28.1 Received proof of Service Request, check claims")
                client = OpaClient(
                    host=self.opa_address,
                    port=int(self.opa_port),
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
                        # TODO delete this object from storage
                request_with_pv = {
                    "input": {
                        "object": requested_object,
                        "action": requested_action
                    }
                }
                jsondata = JsonSearch(object=self.transformation, mode='j')
                transformation_time = 0
                # check attributes
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

                    # self.log("Is requested attributes contained", is_req_attr_contained)
                    if is_req_attr_contained:
                        # Transform the key name in response into the permission validator name

                        try:
                            # The request requests attributes
                            rsp_attr_name = attr_spec['name']
                        except:
                            # "name" and "names" will not be contained in the same object in request
                            # The request requests attributes group
                            for rsp_group_attr_name in attr_spec['names']:
                                permission_validator_name = jsondata.search_first_value(key=rsp_group_attr_name)
                                # self.log("The revealed attribute group object:",pres['requested_proof']['revealed_attr_groups'][referent])
                                # self.log(pres['requested_proof']['revealed_attr_groups'][referent]['values'],rsp_group_attr_name)
                                # self.log(pres['requested_proof']['revealed_attr_groups'][referent]['values'][rsp_group_attr_name])
                                request_with_pv["input"][permission_validator_name] = \
                                pres['requested_proof']['revealed_attr_groups'][referent]['values'][
                                    rsp_group_attr_name]['raw']
                                # #self.log(
                                #     f"{permission_validator_name}: "
                                #     f"{pres['requested_proof']['revealed_attr_groups'][referent]['values'][rsp_group_attr_name]['raw']}"
                                # )
                        else:
                            start_time = time.process_time()
                            permission_validator_name = jsondata.search_first_value(key=rsp_attr_name)
                            request_with_pv["input"][permission_validator_name] = \
                            pres['requested_proof']['revealed_attrs'][referent]['raw']
                            end_time = time.process_time()
                            transformation_time += (end_time - start_time)
                            # self.log(
                            #     f"{permission_validator_name}: "
                            #     f"{pres['requested_proof']['revealed_attrs'][referent]['raw']}"
                            # )

                    else:
                        self.log(
                            f"{referent}: "
                            "(attribute or attributes group not revealed)"
                        )

                # add predicates:
                for (referent, pred_spec) in pres_req["requested_predicates"].items():
                    is_req_pred_contained = False
                    # Note: response presentation always contains a revealed_attrs key
                    if referent in pres['requested_proof']['predicates']:
                        is_req_pred_contained = True
                    else:
                        self.log("No attributes are revealed")
                        return

                    if is_req_pred_contained:
                        start_time = time.process_time()
                        rsp_pred_name = pred_spec['name']
                        permission_validator_name = jsondata.search_first_value(key=rsp_pred_name)
                        request_with_pv["input"][permission_validator_name] = True
                        end_time = time.process_time()
                        transformation_time += (end_time - start_time)
                        self.log(
                            f"{permission_validator_name}: "
                            f"true"
                        )
                #log_status('TIME transformation in ms in flow 2: ' + str(transformation_time * 1000))
                total_transformation_time += transformation_time * 1000

                # for id_spec in pres["identifiers"]:
                # just print out the schema/cred def id's of presented claims
                # self.log(f"schema_id: {id_spec['schema_id']}")
                # self.log(f"cred_def_id {id_spec['cred_def_id']}")
                # Evaluate the result with OPA
                log_status("#29 Redirect the request to OPA")
                self.log("Input of OPA:", request_with_pv)
                rsp = client.check_permission(input_data=request_with_pv, policy_name=f"{self.acm}", rule_name="allow")
                self.log("The result from OPA: ", rsp["result"])
                if rsp["result"] == True:
                    log_status("#30 The service requester has access to the requested service")
                    self.sock.send(
                        f"The service requester has access to the requested service".encode(encoding='utf-8',
                                                                                            errors='strict'))
                    await self.admin_POST(
                        f"/connections/{self.connection_id}/send-message",
                        {"content": "access allowed" }
                    )
                else:
                    log_status("#30 Access denied")
                    self.sock.send(
                        f"Access denied".encode(encoding='utf-8', errors='strict'))
                    await self.admin_POST(
                        f"/connections/{self.connection_id}/send-message",
                        {"content": "access denied" }
                    )

                #log_status('TIME total_verification_time in ms in flow 2: ' + str(total_verification_time))
                #log_status('TIME total_transformation_time in ms in flow 2: ' + str(total_transformation_time))
                #log_status('TIME total_creation_time in ms in flow 2: ' + str(total_creation_time))
                del client
            else:
                if proof["verified"] == "false":
                    log_status("#28 Validation of VP failed ")
                    self.sock.send(
                        f"flow2 VP Validation failed".encode(encoding='utf-8', errors='strict'))
                    await self.admin_POST(
                        f"/connections/{self.connection_id}/send-message", {"content": "access denied"}
                    )
                # in case there are any other kinds of proofs received
                log_status("#28.1 Received " + pres_req["name"])

    # TODOs Code/Aries/aries-cloudagent-python/aries_cloudagent/indy/sdk/verifier.py verify_presentation
    # TODOS Code/Aries/aries-cloudagent-python/aries_cloudagent/indy/holder.py create_presentation
    async def handle_basicmessages(self, message):
        global total_verification_time
        global total_creation_time
        global total_transformation_time

        # for 49 bytes in an empty string

        log_status(f"receive message, size:" + str(sys.getsizeof(json.dumps(message)) - 49))
        # log_status("-"*60)
        if message["content"] == "clear":
            total_verification_time = 0
            total_creation_time = 0
            total_transformation_time = 0
            #log_status('TIME total_verification_time in ms in flow 1: ' + str(total_verification_time))
            #log_status('TIME total_transformation_time in ms in flow 1: ' + str(total_transformation_time))
            #log_status('TIME total_creation_time in ms in flow 1: ' + str(total_creation_time))

        try:
            msg = json.loads(message["content"])
            flow = msg['flow']
            json_service_request = msg["message"]
            msg_type = json_service_request['message_type']
            requested_object = json_service_request['object']
            requested_action = json_service_request['action']
            # connection_id = json_service_request['connection_id']
        except:
            conn_id = message["connection_id"]
            resp_conn_id = await self.admin_GET(
                f"/connections/{conn_id}"
            )
            their_label = resp_conn_id["their_label"]
            self.sock.send(
                (f"Received message from {their_label} :" + message["content"]).encode(encoding='utf-8',
                                                                                       errors='strict')
            )
        else:
            if (msg_type != 'service_request'):
                self.log("Received Request:")
            else:

                log_status("#21 Receive Service Request")
                self.log("Received Service Request:")
                # start a OPA client
                client = OpaClient(
                    host=self.opa_address,
                    port=int(self.opa_port),
                    version="v1"
                )
                # self.log("Are you running OPA?:", client.check_connection())  # response is  Yes I'm here :)
                policies_list = client.get_policies_list()
                # self.log("All OPA policy lists:", policies_list)
                # get the url of the given policy
                info_list = client.get_policies_info()
                url = info_list[self.acm]['path'][0]

                if flow == 1:
                    #log_status('TIME generate proof in ms in flow 1' + msg["creation_time"])
                    total_creation_time += float(msg["creation_time"])
                    log_status("#22.1 Verify the VP in flow 1")
                    try:
                        indy_proof_request = msg["self_request"]
                        # log_msg(indy_proof_request)
                        presentation = msg["presentation"]
                        # log_msg(presentation)
                        # schemas  = msg["schemas"]
                        # #log_msg(schemas)
                        # cred_defs = msg["cred_defs"]
                        # #log_msg(cred_defs)
                        rev_reg_defs = {}
                        rev_regs = {}

                        schema_id = msg["presentation"]["identifiers"][0]["schema_id"]
                        cred_def_id = msg["presentation"]["identifiers"][0]["cred_def_id"]
                        resp_schema = await self.admin_GET(
                            f"/schemas/{schema_id}"
                        )
                        schemas = {}
                        schemas[schema_id] = resp_schema["schema"]

                        resp_credential_def = await self.admin_GET(
                            f"/credential-definitions/{cred_def_id}"
                        )
                        cred_defs = {}
                        cred_defs[cred_def_id] = resp_credential_def["credential_definition"]

                    except:
                        log_status("No valid structure for flow 1")
                        return
                    else:
                        try:
                            start_time = time.process_time()
                            result = await indy.anoncreds.verifier_verify_proof(
                                json.dumps(indy_proof_request),
                                json.dumps(presentation),
                                json.dumps(schemas),
                                json.dumps(cred_defs),
                                "{}",
                                "{}",
                            )
                            end_time = time.process_time()
                            #log_status(
                            #    'TIME verify presentation in ms in flow 1: ' + str((end_time - start_time) * 1000))
                            total_verification_time += (end_time - start_time) * 1000
                            # log_msg(repr(result))
                        except Exception as err:
                            s = str(err)
                            # log_msg(f"\n::{s}")
                            LOGGER.exception(
                                f"Validation of presentation on nonce={indy_proof_request['nonce']} "
                                "failed with error"
                            )
                            result = False
                        if not result:
                            log_status("#28 Validation of VP failed ")
                            self.sock.send(
                                f"flow1 VP Validation failed".encode(encoding='utf-8', errors='strict'))
                            await self.admin_POST(
                                f"/connections/{self.connection_id}/send-message", {"content": "access denied"}
                            )
                            return
                        elif result == True:
                            log_status("#28 Validation of VP passed ")
                            jsondata = JsonSearch(object=self.transformation, mode='j')
                            request_with_pv = {
                                "input": {
                                    "object": requested_object,
                                    "action": requested_action
                                }
                            }
                            # in flow 1, we assume that no predicates are involved
                            transformation_time = 0
                            for (referent, attr_spec) in indy_proof_request["requested_attributes"].items():

                                try:
                                    # The request requests attributes
                                    rsp_attr_name = attr_spec['name']
                                except:
                                    # "name" and "names" will not be contained in the same object in request
                                    # The request requests attributes group
                                    for rsp_group_attr_name in attr_spec['names']:
                                        permission_validator_name = jsondata.search_first_value(key=rsp_group_attr_name)
                                        # self.log("The revealed attribute group object:",
                                        #          presentation['requested_proof']['revealed_attr_groups'][referent])
                                        # self.log(presentation['requested_proof']['revealed_attr_groups'][referent]['values'],
                                        #          rsp_group_attr_name)
                                        # self.log(presentation['requested_proof']['revealed_attr_groups'][referent]['values'][
                                        #              rsp_group_attr_name])
                                        request_with_pv["input"][permission_validator_name] = \
                                            presentation['requested_proof']['revealed_attr_groups'][referent]['values'][
                                                rsp_group_attr_name]['raw']
                                        # self.log(
                                        #     f"{permission_validator_name}: "
                                        #     f"{presentation['requested_proof']['revealed_attr_groups'][referent]['values'][rsp_group_attr_name]['raw']}"
                                        # )
                                else:
                                    start_time = time.process_time()
                                    permission_validator_name = jsondata.search_first_value(key=rsp_attr_name)
                                    request_with_pv["input"][permission_validator_name] = \
                                        presentation['requested_proof']['revealed_attrs'][referent]['raw']
                                    end_time = time.process_time()
                                    transformation_time += (end_time - start_time)
                                    # self.log(
                                    #     f"{permission_validator_name}: "
                                    #     f"{presentation['requested_proof']['revealed_attrs'][referent]['raw']}"
                                    # )

                            #log_status('TIME transformation in ms in flow 1: ' + str(transformation_time * 1000))
                            total_transformation_time += transformation_time * 1000
                            log_status("#29 Redirect the request to OPA")
                            self.log("Input of OPA:", request_with_pv)
                            rsp = client.check_permission(input_data=request_with_pv, policy_name=f"{self.acm}",
                                                          rule_name="allow")
                            self.log("The result from OPA: ", rsp["result"])
                            if rsp["result"] == True:
                                log_status("#30 The service requester has access to the requested service")
                                self.sock.send(
                                    f"The service requester has access to the requested service".encode(
                                        encoding='utf-8',
                                        errors='strict'))
                                await self.admin_POST(
                                    f"/connections/{self.connection_id}/send-message", {"content": "access allowed"}
                                )
                            else:
                                log_status("#30 Access denied")
                                self.sock.send(
                                    f"Access denied".encode(encoding='utf-8', errors='strict'))
                                await self.admin_POST(
                                    f"/connections/{self.connection_id}/send-message", {"content": "access denied"}
                                )

                            #log_status('TIME total_verification_time in ms in flow 1: ' + str(total_verification_time))
                            #log_status(
                            #    'TIME total_transformation_time in ms in flow 1: ' + str(total_transformation_time))
                            #log_status('TIME total_creation_time in ms in flow 1: ' + str(total_creation_time))
                            del client
                elif flow == 2:
                    log_status("#22 Fetch requested information from opa")
                    get_requested_pv = {
                        "input": {
                            "object": requested_object,
                            "action": requested_action
                        }
                    }
                    rsp = requests.post(url, json=get_requested_pv)
                    rsp_str = str(rsp.content, encoding="utf-8")
                    rsp_decoded = json.loads(rsp_str)
                    self.log("Response from OPA", rsp_decoded)
                    requested_attrs_df = rsp_decoded['result']['requested_attrs']
                    requested_preds_df = rsp_decoded['result']['requested_preds']
                    self.log("Requested DFs for the given object and action:", requested_attrs_df, requested_preds_df)
                    # store the request with the connection in storage
                    log_status("#23 Generate and send proof request")
                    service_request = {self.connection_id: {"object": requested_object, "action": requested_action}}
                    service_request_storage.append(service_request)
                    # self.log("service_request_storage", service_request_storage)
                    req_attrs = []
                    req_preds = []
                    jsondata = JsonSearch(object=self.transformation, mode='j')
                    # add requested attributes
                    for requested_attr in requested_attrs_df:
                        all_path = jsondata.search_all_path(key=requested_attr)
                        all_value = jsondata.search_all_value(key=requested_attr)
                        for i in range(0, len(all_path)):
                            req_attrs.append({"name": all_value[i], "restrictions": [
                                {"schema_name": all_path[i][0], "issuer_did": all_path[i][1]}]})
                            # req_attrs.append({"name":all_value[i],"restrictions": [{"cred_def_id": all_path[i][1]}]})
                            # self.log("Adding requested attributes:", req_attrs)

                    # add requested predicates
                    for requested_pred in requested_preds_df:
                        # get either higher or lower
                        if requested_pred["type"] in ["<", "<="]:
                            p_value = requested_pred["lower_than"]
                        elif requested_pred["type"] in [">", ">="]:
                            p_value = requested_pred["higher_than"]
                        all_path = jsondata.search_all_path(key=requested_pred["key"])
                        all_value = jsondata.search_all_value(key=requested_pred["key"])
                        for i in range(0, len(all_path)):
                            req_preds.append({"name": all_value[i],
                                              "p_type": requested_pred["type"],
                                              "p_value": int(p_value),
                                              "restrictions": [
                                                  {"schema_name": all_path[i][0], "issuer_did": all_path[i][1]}]})
                            # self.log("Adding requested predicates:", req_preds)

                    # form indy proof request
                    indy_proof_request = {
                        "name": "Proof of Service Request",
                        "version": "1.0",
                        "nonce": str(uuid4().int),
                        "requested_attributes": {
                            f"0_{req_attr['name']}_uuid": req_attr for req_attr in req_attrs
                        },
                        "requested_predicates": {
                            f"0_{req_pred['name']}_GE_uuid": req_pred for req_pred in req_preds
                        }
                    }
                    self.log("Generate indy proof request", indy_proof_request)
                    self.log("connection ID", self.connection_id)
                    # form the request
                    final_proof_request = {
                        "connection_id": self.connection_id,
                        "presentation_request": {"indy": indy_proof_request},
                    }
                    self.log("Transformed proof request", final_proof_request)
                    await self.admin_POST(
                        "/present-proof-2.0/send-request",
                        final_proof_request
                    )
                    self.log("Send proof request")
                    del client


async def create_agent_with_json(json):
    if ("did_exchange" in json and json["did_exchange"]) and args["mediation"]:
        raise Exception(
            "DID-Exchange connection protocol is not (yet) compatible with mediation"
        )

    if "revocation" in json and json["revocation"]:
        tails_server_base_url = json["tails_server_base_url"] or os.getenv(
            "PUBLIC_TAILS_URL"
        )
    else:
        tails_server_base_url = None

    arg_file = json["arg_file"] if "arg_file" in json else os.getenv("ACAPY_ARG_FILE")
    arg_file_dict = {}
    if arg_file:
        with open(arg_file) as f:
            arg_file_dict = yaml.safe_load(f)

    # if we don't have a tails server url then guess it
    if ("revocation" in json and json["revocation"]) and not tails_server_base_url:
        # assume we're running in docker
        tails_server_base_url = (
                "http://" + (os.getenv("DOCKERHOST") or "host.docker.internal") + ":6543"
        )

    if ("revocation" in json and json["revocation"]) and not tails_server_base_url:
        raise Exception(
            "If revocation is enabled, --tails-server-base-url must be provided"
        )

    multi_ledger_config_path = None
    genesis = None
    if "genesis_url" in json:
        async with ClientSession() as session:
            async with session.get(
                    json["genesis_url"]
            ) as resp:
                genesis = await resp.text()
    if "multi_ledger" in json and json["multi_ledger"]:
        multi_ledger_config_path = "./demo/multi_ledger_config.yml"
    elif not genesis:
        genesis = await default_genesis_txns()
    if not genesis and not multi_ledger_config_path:
        print("Error retrieving ledger genesis transactions")
        sys.exit(1)

    agent_ident = json["ident"] if "ident" in json else "Aries"

    if "aip" in json:
        aip = int(json["aip"])
        if aip not in [
            10,
            20,
        ]:
            raise Exception("Invalid value for aip, should be 10 or 20")
    else:
        aip = 20

    if "cred_type" in json and json["cred_type"] != CRED_FORMAT_INDY:
        public_did = None
        aip = 20
    elif "cred_type" in json and json["cred_type"] == CRED_FORMAT_INDY:
        public_did = True
    else:
        public_did = json["public_did"] if "public_did" in json else None

    cred_type = json["cred_type"] if "cred_type" in json else None
    log_msg(
        f"Initializing demo agent {agent_ident} with AIP {aip} and credential type {cred_type}"
    )

    reuse_connections = "reuse_connections" in json and json["reuse_connections"]
    if reuse_connections and aip != 20:
        raise Exception("Can only specify `--reuse-connections` with AIP 2.0")

    agent = AgentContainer(
        genesis_txns=genesis,
        genesis_txn_list=multi_ledger_config_path,
        ident=agent_ident + ".agent",
        start_port=int(json["port"]) if ("port" in json) else 8000,
        no_auto=json["no_auto"] if ("no_auto" in json) else False,
        revocation=json["revocation"] if "revocation" in json else False,
        tails_server_base_url=tails_server_base_url,
        show_timing=json["timing"] if ("timing" in json) else False,
        multitenant=json["multitenant"] if ("multitenant" in json) else False,
        mediation=json["mediation"] if ("mediation" in json) else False,
        cred_type=cred_type,
        use_did_exchange=(aip == 20) if ("aip" in json) else (
            json["did_exchange"] if ("did_exchange" in json) else False),
        wallet_type=arg_file_dict.get("wallet-type") or json["wallet_type"] if ("wallet_type" in json) else None,
        public_did=public_did,
        seed=json["seed"] if "seed" in json else "random",
        arg_file=arg_file,
        aip=aip,
        endorser_role=json["endorser_role"] if ("endorser_role" in json) else None,
        reuse_connections=reuse_connections,
        taa_accept=json["taa_accept"] if ("taa_accept" in json) else False,
    )
    log_status("Successfully create agent with json")
    return agent


async def create_agent(json):
    log_status("Start creating agent")
    gui_agent = await create_agent_with_json(json)

    try:
        log_status(
            "#1 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {gui_agent.wallet_type})"
                if gui_agent.wallet_type
                else ""
            )
        )
        # log_status("Problems here")
        agent = GuiAgent(
            "gui.agent",
            gui_agent.start_port,
            gui_agent.start_port + 1,
            # external_host = json["external_host"] if "external_host" in json else None,
            genesis_data=gui_agent.genesis_txns,
            genesis_txn_list=gui_agent.genesis_txn_list,
            no_auto=gui_agent.no_auto,
            tails_server_base_url=gui_agent.tails_server_base_url,
            timing=gui_agent.show_timing,
            multitenant=gui_agent.multitenant,
            mediation=gui_agent.mediation,
            wallet_type=gui_agent.wallet_type,
            wallet_name=json["wallet_name"] if "wallet_name" in json else None,
            wallet_key=json["wallet_key"] if "wallet_key" in json else None,
            loading_wallet=json["loading_wallet"] if "loading_wallet" in json else False,
            seed=gui_agent.seed,
            opa_address=json["opa_address"],
            opa_port=json["opa_port"],
            transformation=json["transformation"],
            acm=json["acm"]
        )
        log_status(repr(agent))
        await gui_agent.initialize(
            the_agent=agent,
        )
        log_status("Successfully initialize the agent")
        return gui_agent
    except Exception as e:
        log_status("Fail to create" + repr(e))
        terminated = await gui_agent.terminate()
        return "Error failed to create agent"


async def main(args):
    gui_agent = await create_agent_with_args(args, ident="gui")

    try:
        log_status(
            "#1 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {gui_agent.wallet_type})"
                if gui_agent.wallet_type
                else ""
            )
        )
        agent = GuiAgent(
            "gui.agent",
            gui_agent.start_port,
            gui_agent.start_port + 1,
            genesis_data=gui_agent.genesis_txns,
            genesis_txn_list=gui_agent.genesis_txn_list,
            no_auto=gui_agent.no_auto,
            tails_server_base_url=gui_agent.tails_server_base_url,
            timing=gui_agent.show_timing,
            multitenant=gui_agent.multitenant,
            mediation=gui_agent.mediation,
            wallet_type=gui_agent.wallet_type,
            seed=gui_agent.seed,
        )
        await gui_agent.initialize(
            the_agent=agent,
        )

        # generate an invitation for Alice
        await gui_agent.generate_invitation(display_qr=True, wait=True)

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
                exchange_tracing = False
                log_status("#13 Issue credential offer to X")
                if gui_agent.aip == 10:
                    offer_request = gui_agent.agent.generate_credential_offer(
                        gui_agent.aip, None, gui_agent.cred_def_id, exchange_tracing
                    )
                    await gui_agent.agent.admin_POST(
                        "/issue-credential/send-offer", offer_request
                    )

                elif gui_agent.aip == 20:
                    if gui_agent.cred_type == CRED_FORMAT_INDY:
                        offer_request = gui_agent.agent.generate_credential_offer(
                            gui_agent.aip,
                            gui_agent.cred_type,
                            gui_agent.cred_def_id,
                            exchange_tracing,
                        )

                    elif gui_agent.cred_type == CRED_FORMAT_JSON_LD:
                        offer_request = gui_agent.agent.generate_credential_offer(
                            gui_agent.aip,
                            gui_agent.cred_type,
                            None,
                            exchange_tracing,
                        )

                    else:
                        raise Exception(
                            f"Error invalid credential type: {gui_agent.cred_type}"
                        )

                    await gui_agent.agent.admin_POST(
                        "/issue-credential-2.0/send-offer", offer_request
                    )

                else:
                    raise Exception(f"Error invalid AIP level: {gui_agent.aip}")

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

        if gui_agent.show_timing:
            timing = await gui_agent.agent.fetch_timing()
            if timing:
                for line in gui_agent.agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = await gui_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    parser = arg_parser(ident="gui", port=8040)
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
                "gui remote debugging to "
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
