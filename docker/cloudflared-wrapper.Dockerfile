FROM cloudflare/cloudflared:2024.12.2@sha256:cb38f3f30910a7d51545118a179b8516eb7066eac61855d62ce6ed733c54ce70 AS cloudflared-bin

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache ca-certificates

COPY --from=cloudflared-bin /usr/local/bin/cloudflared /usr/local/bin/cloudflared

WORKDIR /home/nonroot

ENTRYPOINT ["cloudflared", "--no-autoupdate"]
CMD ["version"]
