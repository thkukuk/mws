FROM registry.opensuse.org/opensuse/tumbleweed:latest AS build-stage
RUN zypper install --no-recommends --auto-agree-with-product-licenses -y git go make
#RUN git clone https://github.com/thkukuk/mws
COPY . mws
RUN cd mws && make update && make tidy && make

FROM registry.opensuse.org/opensuse/busybox:latest
LABEL maintainer="Thorsten Kukuk <kukuk@thkukuk.de>"

ARG BUILDTIME=
ARG VERSION=unreleased
LABEL org.opencontainers.image.title="Mini-Webserver (mws) and Reverse Proxy Container"
LABEL org.opencontainers.image.description="Mini-Webserver (mws) is a small webserver for static web pages, which can also act as Reverse Proxy. It supports http and https and is written in go."
LABEL org.opencontainers.image.created=$BUILDTIME
LABEL org.opencontainers.image.version=$VERSION

COPY --from=build-stage /mws/bin/mws /usr/local/bin
COPY entrypoint.sh /

EXPOSE 80/tcp 443/tcp

#HEALTHCHECK --interval=60s --timeout=15s \
#            CMD curl --fail http://localhost:8080/healthz || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/local/bin/mws"]
