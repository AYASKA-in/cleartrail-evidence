FROM clamav/clamav:1.5.4@sha256:e19130cdebaeacc71fa46eab3ed6f69941f2f22aa5e08d55e9197f8edf43ce5e
# The upstream image's Alpine 3.24.2 libc has a vendor-fixed advisory.
RUN apk add --no-cache --upgrade musl=1.2.6-r3 musl-utils=1.2.6-r3
USER 100:101
ENTRYPOINT ["/usr/sbin/clamd"]
CMD ["--config-file=/etc/clamav/clamd.conf"]
