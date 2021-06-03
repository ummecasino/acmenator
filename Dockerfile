FROM golang:1.13-alpine3.10 as build
LABEL maintainer="Alex Vette <umme@posteo.de>"

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . . 
RUN go build -o acmenator .

FROM alpine:3.13
WORKDIR /app
COPY --from=build /app/acmenator .
ENTRYPOINT ["./acmenator"]
