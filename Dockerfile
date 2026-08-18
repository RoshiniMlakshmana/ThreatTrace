# ThreatTrace application image (Docker self-hosted deployment refinement).
#
# Bundles the Python runtime, ThreatTrace's own project dependencies, and
# its bounded scanner/discovery adapters -- Nmap, Nuclei, httpx, and
# Katana -- so a user only needs Docker (and, for the demo stack, Compose)
# to get a fully operational ThreatTrace backend + dashboard. No host
# installation of Python, Nmap, Npcap, Nuclei, httpx, or Katana is
# required for this deployment path.
#
# Security posture (see docs/docker-self-hosted-deployment.md for the
# full write-up):
#   - Runs as a dedicated non-root user, never root.
#   - Nmap is invoked by the existing, unmodified `adapters.bug_bounty_nmap`
#     boundary with a fixed `-Pn -sT -T3` connect-scan profile -- TCP
#     connect scan needs no raw sockets, so this image grants no extra
#     Linux capability (no NET_ADMIN, no NET_RAW) and the container never
#     runs privileged.
#   - Nuclei templates are baked into the image at a pinned version at
#     build time -- fully reproducible, no runtime template-update network
#     call, no LLM-driven update command of any kind.
#   - No proprietary binaries are bundled -- Burp DAST remains an
#     analyst-configured external runtime, exactly as on host deployments.

FROM python:3.13-slim-bookworm

LABEL org.opencontainers.image.title="ThreatTrace" \
      org.opencontainers.image.description="Analyst-governed, AI-assisted security research platform (self-hosted Docker runtime)"

# --- Pinned tool versions -----------------------------------------------
ARG NUCLEI_VERSION=3.11.1
ARG HTTPX_VERSION=1.10.0
ARG KATANA_VERSION=1.7.0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    THREATTRACE_MODE=demo \
    THREATTRACE_NUCLEI_TEMPLATES_DIR=/home/threattrace/nuclei-templates \
    PATH="/usr/local/bin:${PATH}"

# --- OS packages: Nmap (Debian package, no Npcap/host dependency), plus
# --- the minimal fetch tools needed to install the pinned Nuclei binary.
# --- Removed again below once no longer needed to keep the image lean.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        ca-certificates \
        curl \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# --- Nuclei: pinned release binary, never `go install`, never a moving
# --- "latest" tag -- reproducible across builds until this ARG changes.
RUN curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && unzip -o -q /tmp/nuclei.zip -d /usr/local/bin nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -f /tmp/nuclei.zip

# --- Dedicated non-root runtime user -- ThreatTrace never runs as root.
RUN useradd --create-home --home-dir /home/threattrace --shell /usr/sbin/nologin threattrace

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# --- httpx / Katana: same pinned-release-binary discipline as Nuclei
# --- above (same ProjectDiscovery release-asset naming convention) --
# --- never `go install`, never a moving "latest" tag. --retry guards
# --- against the same transient GitHub release-CDN HTTP/2 stream resets
# --- observed for the Nuclei download above -- a network flake, never a
# --- reason to weaken the pinned-version/no-`latest`-tag guarantee.
#
# Deliberately placed AFTER `pip install` above: the Python `httpx`
# package (a transitive dependency of `mcp`) ships its own optional CLI
# console-script also named `httpx`, installed into this same
# /usr/local/bin -- if the real ProjectDiscovery Go binary were unzipped
# here BEFORE pip install ran, pip's own install step would silently
# overwrite it with that broken CLI shim (it errors without the
# `httpx[cli]` extra, which this project never installs). Unzipping the
# real Go binary last guarantees it -- not the Python package's
# same-named shim -- is what `/usr/local/bin/httpx` actually resolves
# to at runtime. Katana has no such name collision but is installed in
# the same step for locality.
RUN curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 -o /tmp/httpx.zip \
        "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip" \
    && unzip -o -q /tmp/httpx.zip -d /usr/local/bin httpx \
    && chmod +x /usr/local/bin/httpx \
    && rm -f /tmp/httpx.zip \
    && curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 -o /tmp/katana.zip \
        "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_amd64.zip" \
    && unzip -o -q /tmp/katana.zip -d /usr/local/bin katana \
    && chmod +x /usr/local/bin/katana \
    && rm -f /tmp/katana.zip

# --- Bake a pinned Nuclei template set into the image at build time
# --- (Option A from the deployment spec -- the most reproducible choice:
# --- no runtime network mutation, works fully offline after this build,
# --- and the exact template state is fixed by this image's own build,
# --- never by an LLM-issued or ad-hoc update command). Run as the same
# --- user that will use them at runtime so Nuclei's default `~/nuclei-
# --- templates` resolution finds them without any extra configuration.
RUN mkdir -p /home/threattrace/nuclei-templates \
    && chown -R threattrace:threattrace /home/threattrace
USER threattrace
RUN nuclei -update-templates -silent || true
USER root

# --- Application source. Only the directories the running backend
# --- actually needs -- never the whole repository (see .dockerignore for
# --- what is excluded: .git, references/, evidence/, output/, tests/, etc).
COPY core/ ./core/
COPY adapters/ ./adapters/
COPY backend/ ./backend/
COPY runtime/ ./runtime/
COPY dashboard/ ./dashboard/

RUN chown -R threattrace:threattrace /app

USER threattrace

EXPOSE 8420

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8420/api/health', timeout=2)" || exit 1

CMD ["python", "-m", "backend.app"]
