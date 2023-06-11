import os
import sys
import subprocess
import PyQt5
import socket
import time
import json
from threading import Thread

from PyQt5 import uic
from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtWidgets import QTableWidgetItem, QInputDialog, QWidget, QLineEdit, QApplication, QMainWindow, QPushButton, \
    QPlainTextEdit, QMessageBox, QDialog

PORT = int(sys.argv[1]) + 3
AGENT_NAME = sys.argv[2]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


class SetSignals(QObject):
    # text_print = pyqtSignal(QTextBrowser,str)
    set_response = pyqtSignal(str)
    set_response_start = pyqtSignal(str)
    set_response_provision = pyqtSignal(str)
    set_response_operations = pyqtSignal(str)
    receive_response_json = pyqtSignal(str)


# Instance of Signal
set_signals = SetSignals()


class MainMenu:

    def __init__(self):
        # Load ui file
        self.ui = uic.loadUi("main_menu.ui")
        self.provision_config = ProvisionConfig()
        self.start_config = StartConfig()
        # band components
        self.band()

    def band(self):
        self.ui.startButton.clicked.connect(self.handle_click_start)
        self.ui.provisionButton.clicked.connect(self.handle_click_provision)

    def handle_click_start(self):
        # msg = "clicked start button in GUI"
        # print(client_send_msg(msg))
        self.start_config.ui.show()
        self.ui.close()

    def handle_click_provision(self):
        # msg = "clicked provision button in GUI"
        # s.send(msg.encode(encoding='utf-8', errors='strict'))
        # print(s.recv(1024).decode(encoding='utf-8', errors='strict'))
        self.provision_config.ui.show()


class StartConfig:
    def __init__(self):
        # Load ui file
        self.ui = uic.loadUi("start_widget.ui")
        self.agent_operations = AgentOperations()
        # band components
        self.band()

    def band(self):
        self.ui.startAgentButton.clicked.connect(self.handle_click_start_agent)
        self.ui.agentOperationsButton.clicked.connect(self.handle_click_agent_operations)
        set_signals.set_response_start.connect(self.set_response)

    def set_response(self, response):
        self.ui.responseTextBrowser.setText(response)
        if "Successfully Start agent" in response:
            self.ui.agentOperationsButton.setEnabled(True)
            self.ui.startAgentButton.setEnabled(False)

    def handle_click_agent_operations(self):
        self.ui.close()
        self.agent_operations.ui.show()
        t = Thread(target=self.agent_operations.listen_server, args=())
        t.start()

    def handle_click_start_agent(self):
        msg_json = {}
        msg_json["type"] = "Start"
        # Mandatory arguments for creating an agent
        msg_json["ident"] = AGENT_NAME
        msg_json["port"] = str(PORT - 3)
        msg_json["cred_type"] = self.ui.credentialType.currentText()
        msg_json["genesis_url"] = self.ui.genesisUrl.text()
        # Optional arguments for creating an agent
        if self.ui.externalHost.text():
            msg_json["external_host"] = self.ui.externalHost.text()
        if self.ui.walletName.text() and self.ui.walletKey.text():
            msg_json["wallet_type"] = self.ui.walletType.currentText()
            msg_json["wallet_name"] = self.ui.walletName.text()
            msg_json["wallet_key"] = self.ui.walletKey.text()
        if self.ui.loadingWallet.isChecked():
            msg_json["loading_wallet"] = True
        if self.ui.seed.text():
            msg_json["seed"] = self.ui.seed.text()
        # arguments for OPA and transformation function
        msg_json["opa_url"] = self.ui.opaUrl.text()
        msg_json["acm"] = self.ui.acm.currentText()
        # load json file from local path
        transformation_path = self.ui.transformationPath.text()
        opa_path = self.ui.opaPolicyPath.text()
        acm = self.ui.acm.currentText()
        transformation = load_file(f"{transformation_path}/transformation_{acm}.json")
        opa_rego = load_file(f"{opa_path}/{acm}.rego")
        opa_data = load_file(f"{opa_path}/{acm}_data.json")
        msg_json["transformation"] = json.loads(transformation)
        msg_json["opa_rego"] = opa_rego
        msg_json["opa_data"] = opa_data
        self.ui.responseTextBrowser.setText(
            "Following message is sended and may need 30-60 seconds waiting for a response: \n\n" + str(msg_json)
        )
        msg_list = []
        msg_list.append(json.dumps(msg_json))
        thread = Thread(target=self.send_msg_to_server,
                        args=(msg_list)
                        )
        thread.start()

    def send_msg_to_server(self, msg_list):
        client_send_msg(msg_list)
        resp = client_receive_msg()
        set_signals.set_response_start.emit(resp)
        return resp


class ProvisionConfig:
    def __init__(self):
        # Load ui file
        self.ui = uic.loadUi("provision_widget.ui")
        # band components
        self.band()

    def band(self):
        self.ui.createWalletButton.clicked.connect(self.handle_click_create_wallet)
        set_signals.set_response_provision.connect(self.set_response)

    def set_response(self, response):
        self.ui.responseTextBrowser.setText(response)

    def handle_click_create_wallet(self):
        msg_json = {}
        msg_json["type"] = "Provision"
        args = ""
        args += "--endpoint http://host.docker.internal:" + str(PORT - 3) + " "
        args += "--wallet-type " + self.ui.walletType.currentText() + " "
        args += "--wallet-name " + self.ui.walletName.text() + " "
        args += "--wallet-key " + self.ui.walletKey.text() + " "
        if self.ui.registeredDID.isChecked():
            args += "--genesis-url " + self.ui.genesisUrl.text() + " "
            args += "--seed " + self.ui.seed.text() + " "
        else:
            args += "--no-ledger"
        msg_json["provision_arguments"] = args
        self.ui.responseTextBrowser.setText(
            "Following message is sended and may need 30-60 seconds waiting for a response: \n\n" + repr(msg_json)
        )
        msg_list = []
        msg_list.append(json.dumps(msg_json))
        thread = Thread(target=self.send_msg_to_server,
                        args=(msg_list)
                        )
        thread.start()

    def send_msg_to_server(self, msg_list):
        client_send_msg(msg_list)
        resp = client_receive_msg()
        set_signals.set_response_provision.emit(resp)
        return resp


class AgentOperations:
    def __init__(self):
        # Load ui file
        self.ui = uic.loadUi("agent_operations.ui")
        self.ui.agentNameLabel.setText(AGENT_NAME)
        self.publish_schema = PublishSchema()
        self.issue_credential = IssueCredential()
        # band components
        self.band()

    def band(self):
        self.ui.generateInvitationButton.clicked.connect(self.handle_click_generate_invitation)
        self.ui.enterInvitationButton.clicked.connect(self.handle_click_enter_invitation)
        self.ui.checkCredentialButton.clicked.connect(self.handle_click_check_credential)
        self.ui.publishSchemaButton.clicked.connect(self.handle_click_publish_schema)
        self.ui.issueCredentialButton.clicked.connect(self.handle_click_issue_credential)
        self.ui.sendMessageButton.clicked.connect(self.handle_click_send_message)
        self.ui.serviceRequestButton.clicked.connect(self.handle_click_service_request)
        # self.ui.exitButton.clicked.connect(self.handle_click_create_wallet)
        set_signals.set_response_operations.connect(self.set_response)

    def set_response(self, response):
        self.ui.responseTextBrowser.setText(response)

    def handle_click_generate_invitation(self):
        msg_json = {}
        msg_json["type"] = "Generate Invitation"
        self.ui.responseTextBrowser.setText(
            "Following message is sended and may need 30-60 seconds waiting for a response: \n\n" + repr(msg_json)
        )
        msg_list = []
        msg_list.append(json.dumps(msg_json))
        thread = Thread(target=self.send_msg_to_server,
                        args=(msg_list)
                        )
        thread.start()

    def handle_click_enter_invitation(self):
        msg_json = {}
        msg_json["type"] = "Enter Invitation"
        inv = self.get_invitation()
        msg_json["invitation"] = inv
        self.ui.responseTextBrowser.setText(
            "Following message is sended and may need 30-60 seconds waiting for a response: \n\n" + repr(msg_json)
        )
        msg_list = []
        msg_list.append(json.dumps(msg_json))
        thread = Thread(target=self.send_msg_to_server,
                        args=(msg_list)
                        )
        thread.start()

    def handle_click_check_credential(self):
        msg_json = {}
        msg_json["type"] = "Check Credential"
        self.ui.responseTextBrowser.setText(
            "Following message is sended and may need 30-60 seconds waiting for a response: \n\n" + repr(msg_json)
        )
        msg_list = []
        msg_list.append(json.dumps(msg_json))
        thread = Thread(target=self.send_msg_to_server,
                        args=(msg_list)
                        )
        thread.start()

    def handle_click_publish_schema(self):
        # self.publish_schema.ui.show()
        self.publish_schema.ui.exec_()
        if not self.publish_schema.ok:
            return
        msg_json = {}
        msg_json["type"] = "Publish Schema"
        msg_json["schema_name"] = self.publish_schema.schema_name
        if self.publish_schema.schema_version:
            msg_json["schema_version"] = self.publish_schema.schema_version
        msg_json["schema_attr"] = self.publish_schema.schema_attr
        self.publish_schema.schema_attr = []
        self.ui.responseTextBrowser.setText(
            "Following message is sended and may need 30-60 seconds waiting for a response: \n\n" + repr(msg_json)
        )
        msg_list = []
        msg_list.append(json.dumps(msg_json))
        thread = Thread(target=self.send_msg_to_server,
                        args=(msg_list)
                        )
        thread.start()

    def handle_click_send_message(self):
        msg_json = {}
        msg_json["type"] = "Send Message"
        message = self.get_message()
        msg_json["message"] = message
        self.ui.responseTextBrowser.setText(
            "Following message is sended and may need 30-60 seconds waiting for a response: \n\n" + repr(msg_json)
        )
        msg_list = []
        msg_list.append(json.dumps(msg_json))
        thread = Thread(target=self.send_msg_to_server,
                        args=(msg_list)
                        )
        thread.start()

    def handle_click_issue_credential(self):
        self.issue_credential.ui.exec_()
        if not self.issue_credential.ok:
            return
        msg_json = {}
        msg_json["type"] = "Issue Credential"
        msg_json["cred_attrs"] = self.issue_credential.cred_attrs
        self.ui.responseTextBrowser.setText(
            "Following message is sended and may need 30-60 seconds waiting for a response: \n\n" + repr(msg_json)
        )
        msg_list = []
        msg_list.append(json.dumps(msg_json))
        thread = Thread(target=self.send_msg_to_server,
                        args=(msg_list)
                        )
        thread.start()

    def handle_click_service_request(self):
        flow = int(self.get_service_request_flow())
        requested_object = self.get_service_object()
        requested_action = self.get_service_action()
        #request_times = self.get_request_times()
        service_request = {
            "message_type": "service_request",
            "object": requested_object,
            "action": requested_action,
            # "connection_id": alice_agent.agent.connection_id
        }
        # service_request_msg = json.dumps(service_request)
        if (not requested_object or not requested_action):
            return
        if (flow == 2):
            msg_json = {}
            msg_json["type"] = "Send Service Request"
            msg_json["flow"] = 2
            #msg_json["req_times"] = request_times
            msg_json["req_times"] = 1
            msg_json["message"] = service_request
        elif (flow == 1):
            # should first choose
            msg_json = {}
            msg_json["type"] = "Send Service Request"
            msg_json["flow"] = 1
            #msg_json["req_times"] = request_times
            msg_json["req_times"] = 1
            msg_json["credential_referent"] = self.get_credential_referent()
            msg_json["message"] = service_request

        # self.ui.time.setText(
        #     str(time.time())
        # )
        self.ui.responseTextBrowser.setText(
            "Following service request message is sended and may need 30-60 seconds waiting for a response: \n\n" + repr(
                msg_json)
        )
        msg_list = []
        msg_list.append(json.dumps(msg_json))
        thread = Thread(target=self.send_msg_to_server,
                        args=(msg_list)
                        )
        thread.start()
        pass

    def get_request_times(self):
        i, okPressed = QInputDialog.getInt(self.ui, "Request Times (For Test)", "times:", 1, 0, 1000, 1)
        if okPressed:
            return i

    def get_credential_referent(self):
        text, okPressed = QInputDialog.getText(self.ui, "Credential", "referent:", QLineEdit.Normal, "")
        if okPressed and text != '':
            return text

    def get_service_request_flow(self):
        items = ["2", "1"]
        item, okPressed = QInputDialog.getItem(self.ui, "Service request flow", "Flow:", items, 0, False)
        if okPressed and item:
            return item

    def get_service_object(self):
        text, okPressed = QInputDialog.getText(self.ui, "Service Object", "Object:", QLineEdit.Normal, "passiblity")
        if okPressed and text != '':
            return text

    def get_service_action(self):
        text, okPressed = QInputDialog.getText(self.ui, "Service Action", "Action:", QLineEdit.Normal, "read")
        if okPressed and text != '':
            return text

    def get_message(self):
        text, okPressed = QInputDialog.getText(self.ui, "Get Message", "Message:", QLineEdit.Normal, "")
        if okPressed and text != '':
            return text

    def get_invitation(self):
        text, okPressed = QInputDialog.getText(self.ui, "Get Invitation", "Invitation:", QLineEdit.Normal, "")
        if okPressed and text != '':
            return text

    def send_msg_to_server(self, msg_list):
        client_send_msg(msg_list)

    def listen_server(self):
        while True:
            resp = client_receive_msg()
            if resp == "server exit":
                self.ui.close()
                break
            try:
                json.loads(resp)
                set_signals.receive_response_json.emit(resp)
            except:
                set_signals.set_response_operations.emit(resp)


class PublishSchema:

    def __init__(self):
        # Load ui file
        self.ui = uic.loadUi("publish_schema_dialog.ui")
        self.schema_name = None
        self.schema_version = None
        self.schema_attr = []
        self.ok = False
        # band components
        self.band()

    def band(self):
        self.ui.attrNumber.valueChanged.connect(self.handle_number_change)
        self.ui.okButton.clicked.connect(self.handle_click_ok)
        self.ui.cancelButton.clicked.connect(self.handle_click_cancel)

    def handle_number_change(self):
        self.ui.schemaAttributes.clear()
        self.ui.schemaAttributes.setRowCount(self.ui.attrNumber.value())

    def handle_click_ok(self):
        self.ok = True
        self.schema_name = self.ui.schemaName.text()
        self.schema_version = self.ui.schemaVersion.text()
        for i in range(self.ui.attrNumber.value()):
            self.schema_attr.append(self.ui.schemaAttributes.item(i, 0).text())
        self.ui.hide()

    def handle_click_cancel(self):
        self.ui.close()


class IssueCredential:

    def __init__(self):
        # Load ui file
        self.ui = uic.loadUi("issue_credential_dialog.ui")
        self.fetch_schema_resp = None
        self.cred_attrs = None
        self.ok = False
        # band components
        self.band()

    def band(self):
        self.ui.schemaName.currentIndexChanged.connect(self.handle_schema_change)
        self.ui.okButton.clicked.connect(self.handle_click_ok)
        self.ui.fetchSchemaButton.clicked.connect(self.handle_click_fetch_schema)
        self.ui.cancelButton.clicked.connect(self.handle_click_cancel)
        set_signals.receive_response_json.connect(self.receive_json_response)

    def receive_json_response(self, response):
        self.fetch_schema_resp = json.loads(response)
        self.ui.schemaName.clear()
        AllItems = [self.ui.schemaName.itemText(i) for i in range(self.ui.schemaName.count())]
        for tag in list(self.fetch_schema_resp.keys()):
            if tag not in AllItems:
                self.ui.schemaName.addItem(tag)

    def handle_schema_change(self):
        tag = self.ui.schemaName.currentText()
        self.ui.schemaAttributes.setRowCount(0)
        self.ui.schemaAttributes.clearContents()
        if not tag or tag == "not yet chose":
            return

        attr_size = len(self.fetch_schema_resp[tag]["credential_definition_attr"])
        self.ui.schemaAttributes.setRowCount(attr_size - 1)
        index = 0
        for i in range(attr_size):
            if self.fetch_schema_resp[tag]["credential_definition_attr"][i] != "master_secret":
                item = QTableWidgetItem()
                item.setText(self.fetch_schema_resp[tag]["credential_definition_attr"][i])
                self.ui.schemaAttributes.setItem(index, 0, item)
                index += 1

    def handle_click_fetch_schema(self):
        msg_json = {}
        msg_json["type"] = "Fetch Schema"
        self.send_msg_to_server(json.dumps(msg_json))

    def handle_click_ok(self):
        try:
            attrs = {}
            for i in range(self.ui.schemaAttributes.rowCount()):
                attr_name = self.ui.schemaAttributes.item(i, 0).text()
                # NOTE all attributes will be stored in the form of string. dont worry about predicates
                attr_value = self.ui.schemaAttributes.item(i, 1).text()
                attrs[attr_name] = attr_value
            self.cred_attrs = {}
            self.cred_attrs[
                self.fetch_schema_resp[self.ui.schemaName.currentText()]["credential_definition_id"]] = attrs
            self.ui.hide()
        except:
            pass
        else:
            self.ok = True

    def handle_click_cancel(self):
        self.ui.close()

    def send_msg_to_server(self, msg):
        client_send_msg(msg)


def client_send_msg(msg):
    s.send(msg.encode(encoding='utf-8', errors='strict'))


def client_receive_msg():
    total_data = bytes()
    while True:
        data = s.recv(1024)
        total_data += data
        if len(data) < 1024:
            break
    return total_data.decode(encoding='utf-8', errors='strict')


def load_file(file_path):
    with open(file_path, encoding='utf-8') as file_obj:
        content = file_obj.read()
    return content


def main():
    print("start running")
    while True:
        time.sleep(5)
        try:
            s.connect(('localhost', PORT))
            s.recv(1024).decode(encoding='utf-8', errors='strict')
            break
        except:
            continue
    # Create a thread to receive messages from server
    app = QApplication([])
    connect_hint = QMessageBox()
    connect_hint.setText("Connect server")
    connect_hint.exec_()
    main_menu = MainMenu()
    main_menu.ui.show()
    app.exec_()


if __name__ == '__main__':
    main()
    print("client ends now")
    client_send_msg("exit")
    s.close()
