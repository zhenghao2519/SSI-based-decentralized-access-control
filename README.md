# SSI-Based Decentralized Access Control

A decentralized access control system supports all kinds of access control models (e.g., ABAC, RBAC, CapBAC) by leveraging Self-sovereign Identity.

## Overview

SSI stands for Self-sovereign Identity.

This directory contains four parts of code, which form an agent representing things in Forestry 4.0. 

1.  `agent_runners`: The agent itself acts as a TCP server and receives commands in JSON form.

2.  `gui`: A pyqt5 GUI is also provided, acting as a client sending commands.
3.  `docker`: dockerfile for building an image, which contains the agent.
4.  `opa`: some example implementation Rego policy used by OPA 

The overall architecture is shown as follows:

![implementation.drawio](implementation_arch.png)

In order to let the agent work properly, a distributed ledger and an external access control engine are required.



The recommended test setup is :

Distributed ledger: [bcgov/von-network: A portable development level Indy Node network. (github.com)](https://github.com/bcgov/von-network)

Access Control Engine: [open-policy-agent/opa: An open source, general-purpose policy engine. (github.com)](https://github.com/open-policy-agent/opa)



However, the system does not depend on certain choices of them. You can use any implementation with the same functionality to replace any of them. (might requires rewriting part of the code)



## Start Agent

To start the agent, please run  `./run_agent.sh <mode> <port> <name> <endpoint> [OPTIONS]`

You can use `` ./run_demo gui --help` for further information.

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

#### Enter Invitation

#### Check Credential

#### Send Message

#### Publish Schema

#### Issue Credential

#### Fetch Schema

#### Send Service Request



