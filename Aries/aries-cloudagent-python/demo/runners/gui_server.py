#!python
# -*- coding=utf-8 -*-
import asyncio
import json
import os
import random
import re
import socket
import subprocess
import sys
import time
from uuid import uuid4

from opa_client.opa import OpaClient

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # noqa

from aries_cloudagent.indy.sdk.holder import (  # noqa:E402
    IndySdkHolder,
)
from aries_cloudagent.indy.sdk.wallet_setup import (  # noqa:E402
    IndyWalletConfig
)

from runners.support.utils import (  # noqa:E402
    log_msg,
    log_status,
    log_timer,
)
from runners.agent_container import (  # noqa:E402
    arg_parser,
    AgentContainer
)
from runners.gui_controller import (  # noqa:E402
    create_agent
)
from aiohttp import (
    ClientSession,
)

DEFAULT_PYTHON_PATH = ".."
PYTHON = os.getenv("PYTHON", sys.executable)
RUNNING_GUI = True
CRED_FORMAT_INDY = "indy"
CRED_FORMAT_JSON_LD = "json-ld"
CRED_PREVIEW_TYPE = "https://didcomm.org/issue-credential/2.0/credential-preview"
client_session = ClientSession()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setblocking(False)
OPEN_WALLET = False
indy_open_wallet = None


async def tcplink(sock, addr, agent_name):
    gui_agent = None
    log_status('Accept new connection from %s : %s ...' % addr)
    sock.send('Welcome!'.encode(encoding='utf-8', errors='strict'))
    # await writer.drain()
    async for msg_json_dumped in server_loop(sock):
        if not msg_json_dumped:
            continue
        if msg_json_dumped == 'exit':
            break

        try:
            msg_json = json.loads(msg_json_dumped)
            log_msg(agent_name + ": " + repr(msg_json))
            mode = msg_json["type"]
        except:
            pass

        if mode == "Provision":  # Provision
            args = msg_json["provision_arguments"]
            provision_resp = ""
            if ("--no-ledger" in args):
                log_msg("No ledger")
            else:
                ledger_url = re.match(r'.*--genesis-url\s(.*?)\s', args, re.DOTALL).group(1)
                ledger_url = ledger_url[0:-8]
                seed = re.match(r'.*--seed\s(.*?)\s', args, re.DOTALL).group(1)
                provision_resp += await provision_register_did(ledger_url=ledger_url, alias=agent_name, seed=seed)
            provision_resp += "\n" + subprocess.getoutput('aca-py provision ' + args)
            log_msg(agent_name + " provision: " + provision_resp)
            if ("Created new profile" in provision_resp):
                provision_resp = "Successfully created wallet with following response!\n\n" + provision_resp
            else:
                provision_resp = "Error! failed to create wallet with following errors\n\n" + provision_resp
            await server_send_msg(sock, provision_resp)
        elif mode == "Start":
            start_resp = ""
            # Load policy into OPA
            opa_url = msg_json["opa_url"]
            log_msg(opa_url)
            opa_address = re.match(r'(.*?):(\d+?)$', opa_url, re.DOTALL).group(1)
            opa_port = re.match(r'(.*?):(\d+?)$', opa_url, re.DOTALL).group(2)
            msg_json["opa_address"] = opa_address
            msg_json["opa_port"] = str(opa_port)
            opa_configuration_resp = configureOPA(opa_address, opa_port, msg_json["opa_rego"], msg_json["opa_data"],
                                                  msg_json["acm"])
            start_resp += opa_configuration_resp

            # Start an agent
            if "wallet_name" not in msg_json or "wallet_key" not in msg_json:
                rand_name = str(random.randint(100_000, 999_999))
                msg_json["wallet_type"] = "indy"
                msg_json["wallet_name"] = "wallet" + rand_name
                msg_json["wallet_key"] = "key" + rand_name

            gui_agent = await create_agent(msg_json)
            gui_agent.agent.sock = sock
            log_msg(repr(gui_agent.agent.sock))

            if (isinstance(gui_agent, AgentContainer)):
                create_agent_resp = "\n\nSuccessfully Start agent with following configurations\n"
                create_agent_resp += "\nWallet name is :" + gui_agent.agent.wallet_name
                create_agent_resp += "\nWallet key is :" + gui_agent.agent.wallet_key
                # create_agent_resp += "\nDID is :" + gui_agent.agent.did
                resp_did = await gui_agent.agent.admin_GET(
                    "/wallet/did/public"
                )
                create_agent_resp += "\nDID is :" + resp_did["result"]["did"]
                create_agent_resp += "\nVerkey is :" + resp_did["result"]["verkey"]
                # create_agent_resp += "\nSeed is :" + gui_agent.agent.seed
                create_agent_resp += "\nAdmin URL is at:" + gui_agent.agent.admin_url
                create_agent_resp += "\nEndpoint URL is at:" + gui_agent.agent.endpoint
            else:
                create_agent_resp = gui_agent
            start_resp += create_agent_resp
            log_msg(start_resp)
            await server_send_msg(sock, start_resp)
        elif mode == "Generate Invitation":
            generate_invitation_resp = await gui_agent.generate_invitation(display_qr=False, wait=False)
            # generate_invitation_resp = await gui_agent.agent.admin_POST("/connections/create-invitation")
            log_msg("Invitation generated:" + json.dumps(generate_invitation_resp))
            await server_send_msg(sock,
                                  "Invitation generated:\n\n" + json.dumps(generate_invitation_resp["invitation"]))
        elif mode == "Enter Invitation":
            try:
                invitation = json.loads(msg_json["invitation"])
            except:
                await server_send_no_connection_error(sock)
                continue

            # enter_invitation_resp  = await gui_agent.agent.input_invitation(invitation, False)
            gui_agent.agent._connection_ready = asyncio.Future()
            with log_timer("Connect duration:"):
                connection = await gui_agent.input_invitation(invitation, wait=True)
            log_msg("Invitation entered:" + repr(connection))
            if "connection_id" in connection:
                connection_resp = "Successfully create connection! \n\n connection_id: " + connection["connection_id"]
            else:
                connection_resp = "Error while creating connection! \n\n " + json.dumps(connection)
            await server_send_msg(sock, connection_resp)
        elif mode == "Check Credential":
            resp_cred = await gui_agent.agent.admin_GET(
                "/credentials"
            )
            await server_send_msg(sock, "Holding credentials:\n\n" + json.dumps(resp_cred))
        elif mode == "Send Message":
            if not gui_agent.agent.connection_id:
                await server_send_no_connection_error(sock)
                continue
            message = msg_json["message"]
            resp_send_message = await gui_agent.agent.admin_POST(
                f"/connections/{gui_agent.agent.connection_id}/send-message", {"content": message}
            )
            await server_send_msg(sock, "Successfully send messages:\n\n" + json.dumps(resp_send_message))
        elif mode == "Publish Schema":
            schema_name = msg_json["schema_name"]
            schema_attr = msg_json["schema_attr"]
            schema_version = msg_json["schema_version"] if "schema_version" in msg_json else None
            cred_def_id = await gui_agent.create_schema_and_cred_def(
                schema_name, schema_attr, schema_version
            )
            if cred_def_id:
                publish_resp = "Successfully publish schema and cred_def_id\n\ncredentail definition id :" + cred_def_id
            else:
                publish_resp = "Error while publishing schema"
            await server_send_msg(sock, publish_resp)
        elif mode == "Issue Credential":
            if not gui_agent.agent.connection_id:
                await server_send_no_connection_error(sock)
                continue
            cred_attrs = msg_json["cred_attrs"]
            cred_def_id = list(cred_attrs.keys())[0]
            if gui_agent.aip == 10:
                # define attributes to send for credential
                cred_preview = {
                    "@type": CRED_PREVIEW_TYPE,
                    "attributes": [
                        {"name": n, "value": v}
                        for (n, v) in cred_attrs[cred_def_id].items()
                    ],
                }
                offer_request = {
                    "connection_id": gui_agent.agent.connection_id,
                    "cred_def_id": cred_def_id,
                    "comment": f"Offer on cred def id {cred_def_id}",
                    "auto_remove": False,
                    "credential_preview": cred_preview,
                    "trace": False,
                }
            elif gui_agent.aip == 20:
                if gui_agent.cred_type == CRED_FORMAT_INDY:
                    cred_preview = {
                        "@type": CRED_PREVIEW_TYPE,
                        "attributes": [
                            {"name": n, "value": v}
                            for (n, v) in cred_attrs[cred_def_id].items()
                        ],
                    }
                    offer_request = {
                        "connection_id": gui_agent.agent.connection_id,
                        "comment": f"Offer on cred def id {cred_def_id}",
                        "auto_remove": False,
                        "credential_preview": cred_preview,
                        "filter": {"indy": {"cred_def_id": cred_def_id}},
                        "trace": False,
                    }
                elif gui_agent.cred_type == CRED_FORMAT_JSON_LD:
                    offer_request = {
                        "connection_id": gui_agent.agent.connection_id,
                        "filter": {
                            "ld_proof": {
                                "credential": {
                                    "@context": [
                                        "https://www.w3.org/2018/credentials/v1",
                                        "https://w3id.org/citizenship/v1",
                                        "https://w3id.org/security/bbs/v1",
                                    ],
                                    "type": [
                                        "VerifiableCredential",
                                        "PermanentResident",
                                    ],
                                    "id": "https://credential.example.com/residents/1234567890",
                                    "issuer": gui_agent.agent.did,
                                    "issuanceDate": "2020-01-01T12:00:00Z",
                                    "credentialSubject": {
                                        "type": ["PermanentResident"],
                                        "givenName": "ALICE",
                                        "familyName": "SMITH",
                                        "gender": "Female",
                                        "birthCountry": "Bahamas",
                                        "birthDate": "1958-07-17",
                                    },
                                },
                                "options": {"proofType": SIG_TYPE_BLS},
                            }
                        },
                    }
            resp_issue_cred = await gui_agent.agent.admin_POST(
                "/issue-credential-2.0/send-offer", offer_request
            )
            await server_send_msg(sock, "Successfully issue credential\n" + json.dumps(resp_issue_cred))
        elif mode == "Fetch Schema":
            # cred_list = []
            resp_fetch_schema = {}
            resp_cred_def_ids = await gui_agent.agent.admin_GET(
                "/credential-definitions/created"
            )
            log_status(json.dumps(resp_cred_def_ids))
            for cred_def_id in resp_cred_def_ids["credential_definition_ids"]:
                resp_cred_def = await gui_agent.agent.admin_GET(
                    f"/credential-definitions/{cred_def_id}"
                )
                log_status(json.dumps(resp_cred_def))
                tag = resp_cred_def["credential_definition"]["tag"]
                schemaId = resp_cred_def["credential_definition"]["schemaId"]
                cred_json = {}
                cred_json["credential_definition_id"] = cred_def_id
                cred_json["credential_definition_tag"] = tag
                cred_json["credential_definition_attr"] = list(
                    resp_cred_def["credential_definition"]["value"]["primary"]["r"].keys())
                resp_fetch_schema[tag + schemaId] = cred_json
            # resp_fetch_schema["credential_definitions"] = cred_list
            log_status(str(resp_fetch_schema))
            await server_send_msg(sock, json.dumps(resp_fetch_schema))
        elif mode == "Send Service Request":
            request_times = msg_json["req_times"]
            if not gui_agent.agent.connection_id:
                server_send_no_connection_error(sock)
                continue
            if msg_json["flow"] == 2:
                for i in range(0, request_times):
                    resp_send_message = await gui_agent.agent.admin_POST(
                        f"/connections/{gui_agent.agent.connection_id}/send-message", {"content": json.dumps(msg_json)}
                    )
                    await server_send_msg(sock,
                                          "Successfully send service request:\n\n" + json.dumps(resp_send_message))
            if msg_json["flow"] == 1:
                cred_referent = msg_json["credential_referent"]
                try:
                    resp_cred = await gui_agent.agent.admin_GET(
                        f"/credential/{cred_referent}"
                    )
                    # log_msg("Fetch credential by referent", resp_cred)
                except:
                    log_msg("No credential with this referent")
                    continue
                req_attrs = []
                for (attr_name, attr_value) in resp_cred["attrs"].items():
                    req_attrs.append({"name": attr_name})

                # form indy proof request
                indy_proof_request = {
                    "name": "Proof of Service Request",
                    "version": "1.0",
                    "nonce": str(uuid4().int)[0 - 5],
                    "requested_attributes": {
                        f"0_{req_attr['name']}_uuid": req_attr for req_attr in req_attrs
                    },
                    "requested_predicates": {
                    }
                }
                log_msg("Generate indy proof request", indy_proof_request)

                config_json = {}
                config_json["name"] = gui_agent.agent.wallet_name
                config_json["key"] = gui_agent.agent.wallet_key
                log_msg(repr(config_json))
                indy_wallet_config = IndyWalletConfig(config=config_json)
                log_msg("config")
                global indy_open_wallet
                try:
                    temp_indy_open_wallet = await indy_wallet_config.open_wallet(created=True)
                except Exception as err:
                    s = str(err)
                    log_msg(f"\n::{s}")
                    pass
                else:
                    indy_open_wallet = temp_indy_open_wallet
                log_msg("open wallet")

                indy_sdk_holder = IndySdkHolder(wallet=indy_open_wallet)
                log_msg("sdk holder")
                credential_reveal = {
                    "self_attested_attributes": {},
                    "requested_attributes": {
                    },
                    "requested_predicates": {},
                }
                # credential_reveal["requested_attributes"]["req_attr"] = {"cred_id": "6ce78625-470e-4133-b741-bb9789220c19", "revealed": True}
                for req_attr in list(indy_proof_request["requested_attributes"].keys()):
                    credential_reveal["requested_attributes"][req_attr] = {"cred_id": cred_referent, "revealed": True}

                schema_id = resp_cred["schema_id"]
                cred_def_id = resp_cred["cred_def_id"]
                resp_schema = await gui_agent.agent.admin_GET(
                    f"/schemas/{schema_id}"
                )
                schemas = {}
                schemas[schema_id] = resp_schema["schema"]
                resp_credential_def = await gui_agent.agent.admin_GET(
                    f"/credential-definitions/{cred_def_id}"
                )
                cred_defs = {}
                cred_defs[cred_def_id] = resp_credential_def["credential_definition"]
                start_time = time.process_time()
                try:

                    # presentation = asyncio.get_event_loop().run_until_complete(
                    #     indy_sdk_holder.create_presentation(
                    #         presentation_request=indy_proof_request,
                    #         requested_credentials=credential_reveal,
                    #         schemas=schemas,
                    #         credential_definitions=cred_defs
                    #     )
                    # )
                    presentation = await indy_sdk_holder.create_presentation(
                        presentation_request=indy_proof_request,
                        requested_credentials=credential_reveal,
                        schemas=schemas,
                        credential_definitions=cred_defs
                    )
                except Exception as err:
                    s = str(err)
                    log_msg(f"\n::{s}")
                end_time = time.process_time()
                #log_status('TIME generate proof in ms in flow 1: ' + str(((end_time - start_time) * 1000)))
                msg_json["self_request"] = indy_proof_request
                msg_json["presentation"] = json.loads(presentation)
                msg_json["creation_time"] = str((end_time - start_time) * 1000)
                # msg_json["schemas"] = schemas
                # msg_json["cred_defs"] = cred_defs
                log_msg("ready to close wallet")
                # await indy_open_wallet.close()
                # del indy_open_wallet
                resp_send_message = await gui_agent.agent.admin_POST(
                    f"/connections/{gui_agent.agent.connection_id}/send-message", {"content": json.dumps(msg_json)}
                )
                await server_send_msg(sock,
                                      "Successfully send service request:\n\n" + json.dumps(resp_send_message))

    # sock.close()
    log_status('Connection from %s : %s closed.' % addr)


async def server_send_no_connection_error(sock):
    msg = "ERROR! not/wrong connection"
    loop = asyncio.get_event_loop()
    await loop.sock_sendall(sock, msg.encode('utf8'))


async def server_loop(reader):
    while True:
        msg_json_dumped = await server_receive_msg(reader)
        yield msg_json_dumped


async def server_send_msg(sock, msg):
    loop = asyncio.get_event_loop()
    await loop.sock_sendall(sock, msg.encode('utf8'))
    # writer.write(msg.encode(encoding='utf-8', errors='strict'))
    # await writer.drain()


async def server_receive_msg(sock):
    total_data = bytes()
    # loop = asyncio.get_event_loop()
    data = None
    # while not data or len(data) >= 1024:
    while True:
        try:
            loop = asyncio.get_event_loop()
            # data = sock.recv(1024)
            data = await loop.sock_recv(sock, 1024)
        except BlockingIOError as e:
            return None
        # data = await reader.read(1024)
        total_data += data
        if len(data) < 1024:
            break
    return total_data.decode(encoding='utf-8', errors='strict')


async def provision_register_did(
        ledger_url: str = None,
        alias: str = None,
        seed: str = None,
        did: str = None,
        verkey: str = None,
        role: str = "TRUST_ANCHOR",
        cred_type: str = CRED_FORMAT_INDY,
):
    if cred_type == CRED_FORMAT_INDY:
        # if registering a did for issuing indy credentials, publish the did on the ledger
        log_msg(f"Registering DID in provision for {alias} ...")
        if not ledger_url:
            ledger_url = f"http://host.docker.internal:9000"
        data = {"alias": alias}
        if role:
            data["role"] = role
        if did and verkey:
            data["did"] = did
            data["verkey"] = verkey
        elif seed:
            data["seed"] = seed
        log_msg("using ledger: " + ledger_url + "/register")
        # resp = requests.post(ledger_url + "/register", json=data)
        resp = await client_session.post(
            ledger_url + "/register", json=data
        )
        if resp.status != 200:
            return f"Error registering DID {data}, response code {resp.status}"
        nym_info = await resp.json()
        return f"Registered DID: " + nym_info["did"] + "\n" + f"nym_info: {nym_info}"
    elif cred_type == CRED_FORMAT_JSON_LD:
        # TODO register a did:key with appropriate signature type
        pass
    else:
        return "Invalid credential type:" + cred_type


def configureOPA(opa_address, opa_port, opa_rego, opa_data, acm):
    client = OpaClient(
        host=opa_address,
        port=int(opa_port),
        version="v1"
    )
    try:
        log_msg("Are you running OPA?:", client.check_connection())  # response is  Yes I'm here :)

    except Exception as e:
        del client
        return "Error : " + repr(e)
    policies_list = client.get_policies_list()
    log_msg("All OPA policy lists:", policies_list)
    # if acm in policies_list:
    #     del client
    #     return "OPA already have loaded data und policy"
    #
    # else:
    #     log_msg("Successfully add data:", client.update_or_create_opa_data(opa_data, f"test/{acm}data"))
    #     log_msg("Successfully add rego policy:", client.update_opa_policy_fromstring(opa_rego, f"{acm}"))
    #     del client
    #     return "Successfully add rego policy and data"

    log_msg("Successfully add data:", client.update_or_create_opa_data(json.loads(opa_data), f"test/{acm}data"))
    log_msg("Successfully add rego policy:", client.update_opa_policy_fromstring(opa_rego, f"{acm}"))
    del client
    return "Successfully add rego policy and data"


# def run(coroutine):
#     try:
#         coroutine.send(None)
#     except StopIteration as e:
#         return e.value
#
# async def run_server():
#     server = await asyncio.start_server(tcplink, "0.0.0.0", start_port + 3)
#     async with server:
#         await server.serve_forever()

async def main(args):
    start_port = args.port
    agent_name = args.ident
    log_msg("port: " + str(start_port))
    # start_port is the endpoint, start_port+1 is admin, start_port+2 is webhook,start_port+3 is the server for gui
    s.bind(("0.0.0.0", start_port + 3))
    # The size of the waiting list for gui client.
    # There is only one active gui client at the same time
    s.listen(5)
    s.setblocking(False)
    log_status('Waiting for connection...')
    # sock, addr = s.accept()
    loop = asyncio.get_event_loop()
    while True:
        sock, addr = await loop.sock_accept(s)
        loop.create_task(tcplink(sock, addr, agent_name))

    log_status("server closed")


if __name__ == '__main__':
    log_status('Now in __main__')
    parser = arg_parser()
    args = parser.parse_args()
    log_status(args)
    asyncio.get_event_loop().run_until_complete(main(args))
