FROM bcgovimages/von-image:py36-1.15-1

ENV ENABLE_PTVSD 0
ENV ENABLE_PYDEVD_PYCHARM 0
ENV PYDEVD_PYCHARM_HOST "host.docker.internal"

# Download jq
# RUN mkdir bin && curl -L -o bin/jq \
# 	https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 && \
# 	chmod ug+x bin/jq



# ADD aries_cloudagent ./aries_cloudagent
#ADD bin ./bin
ADD README.md ./
# ADD scripts ./scripts
# ADD setup.py ./

# USER root
# RUN export DEBIAN_FRONTEND=noninteractive
# RUN apt-get update
# RUN sh -c '/bin/echo -e "Y" | apt-get install python3.8'
# USER 1000


RUN pip3 install --no-cache-dir aries-cloudagent\
	pip install --no-cache-dir OPA-python-client\
	pip install --no-cache-dir requests\
	pip install --no-cache-dir jsonsearch

# RUN mkdir demo logs && chown -R indy:indy demo logs && chmod -R ug+rw demo logs

# Add and install demo code
# ADD demo/requirements.txt ./demo/requirements.txt
# RUN pip3 install --no-cache-dir -r demo/requirements.txt

# ADD demo ./demo

ADD agent_runners ./agent_runners

#ENTRYPOINT ["bash", "-c", "demo/ngrok-wait.sh \"$@\"", "--"]

ENTRYPOINT ["bash", "-c", "agent_runners/ngrok-wait.sh \"$@\"", "--"]

