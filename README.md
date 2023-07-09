# SSI-Based Decentralized Access Control

A decentralized access control system supports all kinds of access control models (e.g., ABAC, RBAC, CapBAC) by leveraging SSI (Self-sovereign Identity).

## Overview

SSI stands for Self-sovereign Identity.
It consists of two cornerstones: Decentralized Identifier (DID) and Verifiable Credentail (VC) 
This repository provides a general mechanism for IoT devices to use DIDs and VCs for access control.

This directory contains four parts, which form an agent representing a smart thing in IoT world. 

1.  `agent_runners`: The agent itself acts as a TCP server receiving commands in JSON form.
2.  `gui`: A pyqt5 GUI acting as a client sending commands.
3.  `docker`: Dockerfile for building an image, which contains the running agent.
4.  `opa`: Some example Rego policy and JSON data that can be used by OPA 

The overall architecture is shown as follows:

![implementation.drawio](implementation_arch.png)

In order to let the agent work properly, both a distributed ledger and an external access control engine are required.



The recommended setup is :

Distributed ledger: [bcgov/von-network: A portable development level Indy Node network. (github.com)](https://github.com/bcgov/von-network)

Access Control Engine: [open-policy-agent/opa: An open source, general-purpose policy engine. (github.com)](https://github.com/open-policy-agent/opa)



However, the system does not depend on certain choices of them. You can use any implementation with the same functionality to replace any of them. (might need to rewrite part of the code)



## Start Agent

To start the agent, please run  `./run_agent.sh <mode> <port> <name> <endpoint> [OPTIONS]`

For example, you can use ` ./run_agent.sh gui --help` for further information.

There are two agent mode:

- `server`: only run the agent docker.
- `gui`: also call up a GUI client while starting the agent docker.



## Commands

#### Provision 

Create a new wallet that can be used in the later start phase.

#### Start

Start a new agent. If no provisioned wallet is given, a random wallet will be created.

Once the operation menu pops up, you can control the agent by following the given instructions.

#### Generate Invitation

Generate a invitation message that builds peer2peer communication with other agent.
Invitation messages can be sent in any way, including QR code, email, bluetooth, even writing on a letter.

#### Enter Invitation

Enter the invitation message received from other agents.
Once a valid invitation is entered, the agents will automatically connect with each other.

#### Check Credential

Check all VCs hold by the agent.

#### Send Message

Send a text message to the agent you are currently connected with.

#### Publish Schema

Publish a VC Schema on the Distributed Ledger
Notice: Please make sure that the agent already has the right to publish a Schema

#### Issue Credential

Issue a Credential following one of your published schema on the ledger.

#### Fetch Schema

Fetch the name and ID of all your created schema on the ledger.

#### Send Service Request

Send a request asking for certain resources or services from the current connected agent. 
There are two workflows:
1. Explicit authorization flow: VCs contains already explicit access rights, e.g, CapBAC.
2. Impilicit authorization flow: VCs contains only implicit information, which may bring access rights, e.g., DAC,ABAC, RBAC ... 

