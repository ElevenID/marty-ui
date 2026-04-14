FROM cloudflare/cloudflared:2024.12.2 AS cloudflared-bin

FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=cloudflared-bin /usr/local/bin/cloudflared /usr/local/bin/cloudflared

WORKDIR /home/nonroot

ENTRYPOINT ["cloudflared", "--no-autoupdate"]
CMD ["version"]