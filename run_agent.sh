#!/bin/bash

# ignore the difference between uppercase and lowercase
shopt -s nocasematch

# enter the directory this shell files is located in
cd $(dirname $0)

# read the first argument as agent mode
if ! [ -z "$1" ]; then
  AGENT_MODE="$1"
else
  echo "Please enter all required arguments correctly!"
  echo "For more details, run './run_agent.sh --help' or './run_agent.sh -h'."
  exit 1
fi

# display help
if [ "$AGENT_MODE" = "--help" ] || [ "$AGENT_MODE" = "-h" ]; then
  cat <<EOF

Usage:
   ./run_agent.sh <mode> <port> <name> [OPTIONS]

   - <mode> is 'server' or 'gui'. The option 'gui' starts a GUI along with the 
            agent. While the option 'server' only starts the agent itself.
   - <port> is the port that the agent uses. The agent reserves 9 ports after 
            the given port. (e.g., 8000 => 8000-8009)
   - <name> is the name of the agent.
EOF
#    - Options:
#       --events - display on the terminal the webhook events from the ACA-Py agent.
#       --timing - at the end of the run, display timing; relevant to the "performance" agent.
#       --bg - run the agent in the background; for use when using OpenAPI/Swagger interface
#           --trace-log - log trace events to the standard log file
#           --trace-http - log trace events to an http endpoint specified in env var TRACE_TARGET_URL
#           --self-attested - include a self-attested attribute in the proof request/response
#           --webhook-url - send events to an http endpoint specified in env var WEBHOOK_URL
#       debug options: --debug-pycharm-agent-port <port>; --debug-pycharm-controller-port <port>
#                     --debug-pycharm; --debug-ptvsd
# EOF

  exit 0
fi

#check mode validity
if ! [[ "$AGENT_MODE" = "gui" || "$AGENT_MODE" = "server" ]]; then
  echo "Please specify which agent you want to run. Choose from 'server', 'gui'."
  echo "For more details, run './run_agent.sh --help' or './run_agent.sh -h'."
  exit 1
fi

# read the second and third argument as the chosen port and name
if ! [[ -z "$2" || -z "$3" ]]; then
  # both agent port and agent name are given
  AGENT_PORT="$2"
  AGENT_NAME="$3"
else 
  echo "please enter the agent port and agent name."
  echo "For more details, run './run_agent.sh --help' or './run_agent.sh -h'."
  exit 1
fi

# check port validity
if [[ $AGENT_PORT -ge 1 && $AGENT_PORT -le 65526 ]]; then
  # given port is valid
  AGENT_PORT_RANGE=${AGENT_PORT}-$(expr ${AGENT_PORT} + 9)
  echo -e "Running the agent in mode ${AGENT_MODE} with name : ${AGENT_NAME} and port : ${AGENT_PORT}.\n"
else
  # given port is not valid
  echo "Port are not valid, please enter a number between 1-65526"
  exit 1
fi
  

# shift all checked arguments and add following augments into ARGS
shift
shift
shift

# TODO: test and add back all arguments for Options 
ARGS=""
TRACE_ENABLED=""
TRACE_TAG=acapy.events
if ! [ -z "$TRACE_TARGET_URL" ]; then
  TRACE_TARGET=http://${TRACE_TARGET_URL}/
else
  TRACE_TARGET=log
fi
WEBHOOK_TARGET=""
if [ -z "$DOCKER_NET" ]; then
  DOCKER_NET="bridge"
fi
DOCKER_VOL=""

# j=1
# for i in "$@"; do
#   ((j++))
#   if [ ! -z "$SKIP" ]; then
#     SKIP=""
#     continue
#   fi
#   case $i in
#   --events)
#     if [ "${AGENT}" = "performance" ]; then
#       echo -e "\nIgnoring the \"--events\" option when running the ${AGENT} agent.\n"
#     else
#       EVENTS=1
#     fi
#     continue
#     ;;
#   --self-attested)
#     SELF_ATTESTED=1
#     continue
#     ;;
#   --trace-log)
#     TRACE_ENABLED=1
#     TRACE_TARGET=log
#     TRACE_TAG=acapy.events
#     continue
#     ;;
#   --trace-http)
#     TRACE_ENABLED=1
#     TRACE_TARGET=http://${TRACE_TARGET_URL}/
#     TRACE_TAG=acapy.events
#     continue
#     ;;
#   --webhook-url)
#     WEBHOOK_TARGET=http://${WEBHOOK_URL}
#     continue
#     ;;
#   --debug-ptvsd)
#     ENABLE_PTVSD=1
#     continue
#     ;;
#   --debug-pycharm)
#     ENABLE_PYDEVD_PYCHARM=1
#     continue
#     ;;
#   --debug-pycharm-controller-port)
#     PYDEVD_PYCHARM_CONTROLLER_PORT=${!j}
#     SKIP=1
#     continue
#     ;;
#   --debug-pycharm-agent-port)
#     PYDEVD_PYCHARM_AGENT_PORT=${!j}
#     SKIP=1
#     continue
#     ;;
#   --timing)
#     if [ ! -d "../logs" ]; then
#       mkdir ../logs && chmod -R uga+rws ../logs
#     fi
#     if [ "$(ls -ld ../logs | grep dr..r..rwx)" == "" ]; then
#       echo "Error: To use the --timing parameter, the directory '../logs' must exist and all users must be able to write to it."
#       echo "For example, to create the directory and then set the permissions use: 'mkdir ../logs; chmod uga+rws ../logs'"
#       exit 1
#     fi

#     DOCKER_VOL="${DOCKER_VOL} -v C:/Users/42143/Desktop/BA-Arbeit/report/bachelor-thesis-zhenghao-zhang/Code/Aries/aries-cloudagent-python/demo/logs/:/home/indy/logs"
#     DOCKER_VOL="${DOCKER_VOL} -v /$(pwd)/../logs:/home/indy/logs"
#     DOCKER_VOL="${DOCKER_VOL} -v ../logs : /home/indy/logs"
#     continue
#     ;;
#   --bg)
#     if [ "${AGENT}" = "server" ] || [ "${AGENT}" = "gui" ]; then
#       DOCKER_OPTS="-d"
#       echo -e "\nRunning in ${AGENT} in the background. Note that you cannot use the command line console in this mode."
#       echo To see the logs use: \"docker logs ${AGENT}\".
#       echo While viewing logs, hit CTRL-C to return to the command line.
#       echo To stop the agent, use: \"docker stop ${AGENT}\". The docker environment will
#       echo -e "be removed on stop.\n\n"
#     else
#       echo The "bg" option \(for running docker in detached mode\) is only for agents
#       echo Ignoring...
#     fi
#     continue
#     ;;
#   esac
#   ARGS="${ARGS:+$ARGS }$i"
# done

# build docker image
echo "Preparing agent image..."
docker build -q -t agent_image -f ./docker/Dockerfile . || exit 1

if [ ! -z "$DOCKERHOST" ]; then
  # provided via APPLICATION_URL environment variable
  export RUNMODE="docker"
elif [ -z "${PWD_HOST_FQDN}" ]; then
  # getDockerHost; for details refer to https://github.com/bcgov/DITP-DevOps/tree/main/code/snippets#getdockerhost
  . /dev/stdin <<<"$(cat <(curl -s --raw https://raw.githubusercontent.com/bcgov/DITP-DevOps/main/code/snippets/getDockerHost))"
  export DOCKERHOST=$(getDockerHost)
  export RUNMODE="docker"
else
  PWD_HOST="${PWD_HOST_FQDN}"
  if [ "$PWD_HOST_FQDN" = "labs.play-with-docker.com" ]; then
    export ETH_CONFIG="eth1"
  elif [ "$PWD_HOST_FQDN" = "play-with-docker.vonx.io" ]; then
    export ETH_CONFIG="eth0"
  else
    export ETH_CONFIG="eth0"
  fi
  MY_HOST=$(ifconfig ${ETH_CONFIG} | grep inet | cut -d':' -f2 | cut -d' ' -f1 | sed 's/\./\-/g')
  export DOCKERHOST="ip${MY_HOST}-${SESSION_ID}-{PORT}.direct.${PWD_HOST_FQDN}"
  export RUNMODE="pwd"
fi

# TODO: Test and support ngrox
# check if ngrok is running on our $AGENT_PORT (don't override if AGENT_ENDPOINT is already set)
# if [ -z "$AGENT_ENDPOINT" ] && [ "$RUNMODE" == "docker" ]; then
#   echo "Trying to detect ngrok service endpoint"
#   JQ=${JQ:-$(which jq)}
#   if [ -x "$JQ" ]; then
#     NGROK_ENDPOINT=$(curl --silent localhost:4040/api/tunnels | $JQ -r '.tunnels[0].public_url')
#     if [ -z "$NGROK_ENDPOINT" ] || [ "$NGROK_ENDPOINT" = "null" ]; then
#       echo "ngrok not detected for agent endpoint"
#     else
#       export AGENT_ENDPOINT=$NGROK_ENDPOINT
#       echo "Detected ngrok agent endpoint [$AGENT_ENDPOINT]"
#     fi
#   else
#     echo "jq not found"
#   fi
# fi

echo "DOCKERHOST=$DOCKERHOST"

# check global parameters
DOCKER_ENV="-e LOG_LEVEL=${LOG_LEVEL} -e RUNMODE=${RUNMODE} -e DOCKERHOST=${DOCKERHOST}"
if ! [ -z "$AGENT_PORT" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e AGENT_PORT=${AGENT_PORT}"
fi
if ! [ -z "$POSTGRES" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e POSTGRES=1 -e RUST_BACKTRACE=1"
fi
if ! [ -z "$LEDGER_URL" ]; then
  GENESIS_URL="${LEDGER_URL}/genesis"
  DOCKER_ENV="${DOCKER_ENV} -e LEDGER_URL=${LEDGER_URL}"
fi
if ! [ -z "$GENESIS_URL" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e GENESIS_URL=${GENESIS_URL}"
fi
if ! [ -z "$AGENT_ENDPOINT" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e AGENT_ENDPOINT=${AGENT_ENDPOINT}"
fi
if ! [ -z "$EVENTS" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e EVENTS=1"
fi
if ! [ -z "$SELF_ATTESTED" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e SELF_ATTESTED=${SELF_ATTESTED}"
fi
if ! [ -z "$TRACE_TARGET" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e TRACE_TARGET=${TRACE_TARGET}"
  DOCKER_ENV="${DOCKER_ENV} -e TRACE_TAG=${TRACE_TAG}"
  DOCKER_ENV="${DOCKER_ENV} -e TRACE_ENABLED=${TRACE_ENABLED}"
fi
if ! [ -z "$WEBHOOK_TARGET" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e WEBHOOK_TARGET=${WEBHOOK_TARGET}"
fi
# if $TAILS_NETWORK is specified it will override any previously specified $DOCKER_NET
if ! [ -z "$TAILS_NETWORK" ]; then
  DOCKER_NET="${TAILS_NETWORK}"
  DOCKER_ENV="${DOCKER_ENV} -e TAILS_NETWORK=${TAILS_NETWORK}"
  DOCKER_ENV="${DOCKER_ENV} -e TAILS_NGROK_NAME=ngrok-tails-server"
fi
if ! [ -z "$PUBLIC_TAILS_URL" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e PUBLIC_TAILS_URL=${PUBLIC_TAILS_URL}"
fi
if ! [ -z "$TAILS_FILE_COUNT" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e TAILS_FILE_COUNT=${TAILS_FILE_COUNT}"
fi
if ! [ -z "$ACAPY_ARG_FILE" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e ACAPY_ARG_FILE=${ACAPY_ARG_FILE}"
fi

if ! [ -z "${ENABLE_PYDEVD_PYCHARM}" ]; then
  DOCKER_ENV="${DOCKER_ENV} -e ENABLE_PYDEVD_PYCHARM=${ENABLE_PYDEVD_PYCHARM} -e PYDEVD_PYCHARM_CONTROLLER_PORT=${PYDEVD_PYCHARM_CONTROLLER_PORT} -e PYDEVD_PYCHARM_AGENT_PORT=${PYDEVD_PYCHARM_AGENT_PORT}"
fi

echo "DOCKER_ENV=$DOCKER_ENV"

# on Windows, docker run needs to be prefixed by winpty
if [ "$OSTYPE" = "msys" ]; then
  DOCKER="winpty docker"
fi


if [ "$AGENT_MODE" = "gui" ]; then
  echo "starting gui"
  DOCKER=${DOCKER:-docker}
  cd ./GUI
  python pyqt5_gui.py ${AGENT_PORT} ${AGENT_NAME} &
fi

echo "starting server" &
$DOCKER run --name ${AGENT_NAME} --rm -it ${DOCKER_OPTS} \
  --network=${DOCKER_NET} \
  -p 0.0.0.0:$AGENT_PORT_RANGE:$AGENT_PORT_RANGE \
  ${DOCKER_VOL} \
  $DOCKER_ENV \
  agent_image $AGENT_MODE --ident $AGENT_NAME --port $AGENT_PORT $ARGS
