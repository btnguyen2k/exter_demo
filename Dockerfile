FROM alpine:3
RUN mkdir /app
COPY . /app
RUN ls -la /app
RUN apk add --no-cache -U tzdata bash ca-certificates \
    && update-ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Ho_Chi_Minh /etc/localtime \
    && chmod 711 /app/main \
    && rm -rf /var/cache/apk/*
WORKDIR /app
CMD ["/app/main"]
#ENTRYPOINT /app/main
