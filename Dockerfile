FROM golang:1.21.5 AS celestia-das-builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o celestia-server

FROM scratch

COPY --from=celestia-das-builder /app/celestia-server /app/celestia-server

WORKDIR /app

ENTRYPOINT [ "./celestia-server" ]


