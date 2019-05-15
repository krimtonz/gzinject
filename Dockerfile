FROM alpine:3.9 as build-stage
# Install build dependencies
RUN apk --no-cache \
    add --virtual build-dependencies \
    gcc \
    musl-dev \
    make
# Prepare workspace
WORKDIR /usr/local/src/gzinject
COPY . .
# Compile and install
RUN ./configure --prefix=/opt/gzinject
RUN make \
    && make install

# Final image
FROM alpine:3.9
COPY --from=build-stage /opt/gzinject /usr/local
CMD ["/bin/sh"]
