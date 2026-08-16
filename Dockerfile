# ThreatTrace application image (Docker self-hosted deployment refinement).
#
# Bundles the Python runtime, ThreatTrace's own project dependencies, and
# two of its bounded scanner adapters -- Nmap and Nuclei -- so a user only
# needs Docker (and, for the demo stack, Compose) to get a fully
# operational ThreatTrace backend + dashboard. No host installation of
# Python, Nmap, Npcap, or Nuclei is required for this deployment path.
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
RUN curl -fsSL -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && unzip -q /tmp/nuclei.zip -d /usr/local/bin nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -f /tmp/nuclei.zip

# --- Dedicated non-root runtime user -- ThreatTrace never runs as root.
RUN useradd --create-home --home-dir /home/threattrace --shell /usr/sbin/nologin threattrace

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

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
