FROM zeek/zeek:lts

ARG HTTP_PROXY
ARG HTTPS_PROXY

# Switch Debian sources to USTC
RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
    sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list

RUN apt-get update && apt-get install -y \
    cmake make gcc g++ libpcap-dev libssl-dev git python3-dev \
    curl libsasl2-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*


RUN git config --global http.proxy $HTTP_PROXY && \
    git config --global https.proxy $HTTPS_PROXY && \
    git config --global http.sslVerify false

# BUILD LIBRDKAFKA v1.4.4 FROM SOURCE
WORKDIR /tmp
RUN curl -L https://github.com/edenhill/librdkafka/archive/v1.4.4.tar.gz | tar xvz && \
    cd librdkafka-1.4.4/ && \
    ./configure && \
    make && \
    make install && \
    ldconfig && \
    cd /tmp && rm -rf librdkafka-1.4.4

WORKDIR /
RUN zkg autoconfig --force

# Install the requested CISA ICS packages
RUN zkg install --force \
    cisagov/icsnpp-modbus \
    cisagov/icsnpp-s7comm \
    cisagov/icsnpp-opcua-binary \
    cisagov/icsnpp-enip \
    seisollc/zeek-kafka

# Unset proxies so they don't affect runtime traffic capture
ENV HTTP_PROXY=""
ENV HTTPS_PROXY=""
