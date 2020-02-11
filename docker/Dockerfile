FROM debian:stretch

RUN apt-get update && apt-get install -y \
    bison \
    build-essential \
    ca-certificates \
    cmake \
    flex \
    gawk \
    git \
    libcurl4-openssl-dev \
    libgeoip-dev \
    libjemalloc-dev \
    libmaxminddb-dev \
    libncurses5-dev \
    libpcap-dev \
    librocksdb-dev \
    libssl1.0-dev \
    python3-dev \
    python3-pip \
    swig \
    wget \
    zlib1g-dev \
    --no-install-recommends

# get latest zeek from source
WORKDIR /opt
RUN git clone --recursive https://github.com/zeek/zeek /opt/zeek-git
WORKDIR /opt/zeek-git

WORKDIR /tmp/
RUN ./configure --with-jemalloc=/usr/lib/x86_64-linux-gnu --prefix=/usr/local/zeek
RUN make -j4 install

RUN git clone https://github.com/edenhill/librdkafka.git
WORKDIR librdkafka
RUN ./configure  \
  && make \
  && make install

RUN echo "===> Installing apache/metron-bro-plugin-kafka package..." \
  && cd /opt/zeek-git/aux/ \
  && git clone https://github.com/apache/metron-bro-plugin-kafka.git \
  && cd /opt/zeek-git/aux/metron-bro-plugin-kafka \
  && find . -name "*.bro" -exec sh -c 'mv "$1" "${1%.bro}.zeek"' _ {} \; \
  && CC=clang ./configure --bro-dist=/opt/zeek-git \
  && make -j 2 \
  && make install

RUN echo "===> Check if kafka plugin installed..." && /usr/local/zeek/bin/zeek -N Apache::Kafka

RUN echo "===> Shrinking image..." \
  && strip -s /usr/local/zeek/bin/zeek

RUN echo "===> Size of the Zeek install..." \
  && du -sh /usr/local/zeek
####################################################################################################
FROM debian:stretch

LABEL maintainer "Rouzbeh Radparvar"

RUN apt-get install ca-certificates zlib openssl libstdc++ libpcap libmaxminddb libgcc fts librdkafka

COPY --from=builder /usr/local/zeek /usr/local/zeek
COPY local.zeek /usr/local/zeek/share/zeek/site/local.zeek
COPY main.zeek /usr/local/zeek/share/zeek/base/protocols/dns/main.zeek

# Add zeek scripts
COPY scripts /usr/local/zeek/share/zeek/site/scripts

WORKDIR /logs

ENV ZEEKPATH .:/data/config:/usr/local/zeek/share/zeek:/usr/local/zeek/share/zeek/policy:/usr/local/zeek/share/zeek/site
ENV PATH $PATH:/usr/local/zeek/bin

ENTRYPOINT ["zeek"]
CMD ["-h"]