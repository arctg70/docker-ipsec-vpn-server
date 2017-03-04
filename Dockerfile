FROM debian:jessie
MAINTAINER  arctg70 <simon.zhou@gmail.com>

RUN apt-get update && \
    apt-get upgrade -y --force-yes &&\
    apt-get install strongSwan strongswan-plugin-eap-mschapv2 strongswan-plugin-xauth-generic wget 


COPY ./run.sh /opt/src/run.sh
RUN chmod 755 /opt/src/run.sh

EXPOSE 500/udp 4500/udp

VOLUME ["/lib/modules"]
VOLUME ["/data"]

CMD ["/opt/src/run.sh"]
