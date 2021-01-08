FROM ubuntu:20.04 as base 
LABEL maintainer "Rouzbeh Radparvar"


FROM base as builder
ENV ZEEK_VERSION 3.2.3
RUN apt-get update && DEBIAN_FRONTEND="noninteractive" apt-get install -y \
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
  libssl-dev \
  python3-dev \
  python3-pip \
  swig \
  wget \
  zlib1g-dev \
  --no-install-recommends

# get latest zeek from source
RUN git clone --recursive --branch v$ZEEK_VERSION https://github.com/zeek/zeek /opt/zeek-git

WORKDIR /opt/zeek-git
RUN ./configure --with-jemalloc=/usr/lib/x86_64-linux-gnu --prefix=/usr/local/zeek
RUN make -j4 install

RUN git clone https://github.com/edenhill/librdkafka.git
WORKDIR librdkafka
RUN ./configure --prefix=/usr \
  && make \
  && make install \
  && ldconfig && ls /usr

RUN echo "===> Installing apache/metron-bro-plugin-kafka package..." \
  && cd /opt/zeek-git \
  && git clone https://github.com/apache/metron-bro-plugin-kafka.git 

WORKDIR /opt/zeek-git/metron-bro-plugin-kafka
RUN ./configure --zeek-dist=/opt/zeek-git --with-librdkafka=/opt/zeek-git/librdkafka\
  && make -j 2 \
  && make install

RUN  echo "===> Check if kafka plugin installed..." && /usr/local/zeek/bin/zeek -N Apache::Kafka

RUN echo "===> Shrinking image..." \
  && strip -s /usr/local/zeek/bin/zeek

RUN echo "===> Size of the Zeek install..." \
  && du -sh /usr/local/zeek

RUN echo "===> Installing apache/metron-bro-plugin-kafka package..." \
  && cd /opt/zeek-git \
  && git clone https://github.com/corelight/zeek-community-id

WORKDIR /opt/zeek-git/zeek-community-id
RUN ./configure --zeek-dist=/opt/zeek-git \
  && cd build \
  && make \
  && make install
RUN  echo "===> Check if zeek-community-id plugin installed..." && /usr/local/zeek/bin/zeek -N Corelight::CommunityID


FROM base

RUN apt-get update && apt-get install -y libjemalloc2 ca-certificates zlib1g openssl libpcap0.8 libmaxminddb0 libgcc1 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/zeek /usr/local/zeek
COPY --from=builder /usr/lib/librdkafka* /usr/lib/
COPY local.zeek /usr/local/zeek/share/zeek/site/local.zeek
COPY main.zeek /usr/local/zeek/share/zeek/base/protocols/dns/main.zeek

# Add zeek scripts
COPY scripts /usr/local/zeek/share/zeek/site/scripts

WORKDIR /logs

ENV ZEEKPATH .:/data/config:/usr/local/zeek/share/zeek:/usr/local/zeek/share/zeek/policy:/usr/local/zeek/share/zeek/site
ENV PATH $PATH:/usr/local/zeek/bin

ENTRYPOINT ["zeek"]
CMD ["-h"]
