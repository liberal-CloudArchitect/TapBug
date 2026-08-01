FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends gcc socat libc6-dev && rm -rf /var/lib/apt/lists/*
COPY vuln.c /vuln.c
COPY flag.txt /flag.txt
RUN gcc -fno-stack-protector -no-pie -o /vuln /vuln.c
EXPOSE 1338
CMD ["socat","-T120","TCP-LISTEN:1338,reuseaddr,fork","EXEC:/vuln,stderr"]
