FROM golang:1.16.2-alpine AS build

RUN apk add git make openssl

WORKDIR /go/src/github.com/ababoshin/kubernetes-cert-signer
ADD . .
RUN go get -v
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-w -s" -o kubernetes-cert-signer main.go

FROM scratch
WORKDIR /app
COPY --from=build /go/src/github.com/ababoshin/kubernetes-cert-signer/kubernetes-cert-signer .
ENTRYPOINT ["/app/kubernetes-cert-signer"]
