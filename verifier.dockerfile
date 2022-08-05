FROM python:3.9

ARG LISTENING_PORT

EXPOSE ${LISTENING_PORT}:9000

RUN pip3 install Werkzeug
RUN pip3 install jsonpath-ng
RUN pip3 install jwcrypto
RUN pip3 install base58
RUN pip3 install requests

COPY IAA/ IAA/
COPY conf/ conf/
ENTRYPOINT [ "python", "IAA/iaa.py" ]
