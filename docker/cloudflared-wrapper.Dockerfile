FROM cloudflare/cloudflared:2026.11.1@sha256:e613aadbc2d9511785d2e67a86b0c8ac18dd63a3f9af0d06faf04cbfdcb35f2d AS cloudflared-bin

FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

RUN apk add --no-cache ca-certificates

COPY --from=cloudflared-bin /usr/local/bin/cloudflared /usr/local/bin/cloudflared

WORKDIR /home/nonroot

ENTRYPOINT ["cloudflared", "--no-autoupdate"]
CMD ["version"]
