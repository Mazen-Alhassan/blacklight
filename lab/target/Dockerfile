FROM ubuntu:22.04

# The target. Where atomics and benign profiles run. Deliberately looks like an
# ordinary small Linux server: an interpreter, a compiler, the usual admin tools.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      curl wget ca-certificates \
      python3 python3-venv \
      gcc libc6-dev make \
      cron rsync gzip tar xz-utils \
      openssh-client procps iproute2 net-tools \
      sudo passwd kmod \
      vim-tiny less \
 && rm -rf /var/lib/apt/lists/*

# A non-root admin user, the way a real box has one. Some atomics still need root
# (ptrace across users, module load), so the container runs privileged and the
# executor picks the uid per activity.
RUN useradd -m -s /bin/bash -u 1000 admin \
 && echo 'admin ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/admin

WORKDIR /root
CMD ["sleep", "infinity"]
