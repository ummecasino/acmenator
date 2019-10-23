FROM golang:1.13-alpine3.10
LABEL maintainer="Alex Vette <umme@posteo.de>"

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . . 
RUN go build -o acmenator .

ENTRYPOINT ["./acmenator"]
