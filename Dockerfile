FROM perl:5.38-slim

WORKDIR /app

COPY server.pl /app/server.pl
COPY public /app/public
COPY config /app/config

RUN mkdir -p /app/data /app/logs

ENV VSAT_BIND=0.0.0.0
ENV VSAT_PORT=8080

EXPOSE 8080

CMD ["perl", "server.pl"]
