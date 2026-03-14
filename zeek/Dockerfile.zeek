FROM zeek/zeek:lts

# 1. OPTIMIZATION: Switch Debian sources to USTC
RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
    sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list

ARG http_proxy
ARG https_proxy

# Ensure proxy settings apply to all RUN commands (crucial for git/zkg)
ENV HTTP_PROXY=$http_proxy
ENV HTTPS_PROXY=$https_proxy
ENV http_proxy=$http_proxy
ENV https_proxy=$https_proxy

# 2. INSTALL DEPENDENCIES
RUN apt-get update && apt-get install -y \
    cmake make gcc g++ libpcap-dev libssl-dev git python3-dev \
    && rm -rf /var/lib/apt/lists/*

# 3. CONFIGURE ZKG & INSTALL ICSNPP
RUN git config --global http.sslVerify false && \
    zkg autoconfig --force

# Install the requested CISA ICS packages
RUN zkg install --force cisagov/icsnpp-modbus && \
    zkg install --force cisagov/icsnpp-s7comm && \
    zkg install --force cisagov/icsnpp-opcua-binary && \
    zkg install --force cisagov/icsnpp-enip

# 4. FORCE JSON OUTPUT (Critical for modern log aggregation)
RUN echo "@load tuning/json-logs" >> $(zeek-config --site_dir)/local.zeek && \
    echo "@load packages" >> $(zeek-config --site_dir)/local.zeek
    
# Unset proxies so they don't affect runtime traffic capture
ENV HTTP_PROXY=""
ENV HTTPS_PROXY=""
ENV http_proxy=""
ENV https_proxy=""