FROM archlinux:base-devel@sha256:a26046b7363dad8e2614858f4313949ae9b05c9c5f31de343a54864b9e20806f

SHELL ["/usr/bin/bash", "--noprofile", "--norc", "-euxo", "pipefail", "-c"]

RUN printf '%s\n' \
      "Server = https://archive.archlinux.org/repos/2026/08/24/\$repo/os/\$arch" \
      >/etc/pacman.d/mirrorlist \
    && pacman --noconfirm -Syu --needed \
      bash \
      ca-certificates \
      git \
      libarchive \
      shadow \
      systemd \
      unzip \
      util-linux \
      wayland \
      zstd \
    && pacman -Dk \
    && groupadd --gid 1001 a-quo-observer \
    && useradd --create-home --home-dir /home/a-quo-observer \
      --uid 1001 --gid 1001 a-quo-observer \
    && install -d -o 1001 -g 1001 -m 0755 /workspace

LABEL org.opencontainers.image.title="A Quo reviewed x86_64 isolated lifecycle environment" \
      org.opencontainers.image.description="Architecture-matched private fakeroot/libalpm package transition" \
      org.opencontainers.image.source="https://github.com/SurreptitiousFabric/a-quo" \
      org.opencontainers.image.architecture="amd64" \
      org.opencontainers.image.a-quo-lifecycle="isolated-fakeroot-libalpm-reviewed"
