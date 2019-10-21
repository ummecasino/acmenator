FROM scratch
LABEL maintainer="Alex Vette <umme@posteo.de>"

COPY target/acmenator /acmenator
ENTRYPOINT ["./acmenator"]
