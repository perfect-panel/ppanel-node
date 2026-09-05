# Build go
FROM golang:1.27.1-alpine AS builder
WORKDIR /app
COPY . .
ENV CGO_ENABLED=0
RUN go mod download
RUN go build -v -o ./output/ppnode -trimpath -ldflags "-s -w -buildid="

# Release
FROM  alpine
# 安装必要的工具包
RUN  apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
RUN mkdir /etc/PPanel-node/
COPY --from=builder /app/output/ppnode /usr/local/bin

ENTRYPOINT [ "ppnode", "server", "--config", "/etc/PPanel-node/config.yml"]
