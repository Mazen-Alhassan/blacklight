FROM ubuntu:22.04

# The sensor. Runs auditd against the single host kernel audit subsystem.
# Only one auditd can own the kernel netlink, so this is the one sensor in the lab.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends auditd \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
