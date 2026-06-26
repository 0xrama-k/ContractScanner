# Sandbox image for running Slither on a single Solidity file (Section 15).
#
# At runtime the backend runs this with: --network none, memory/cpu/pids limits,
# --rm, and the scan folder bind-mounted at /scan. The container is ephemeral.
#
# V1 note: runs as root inside the isolated, network-less, resource-capped,
# single-file ephemeral container. Non-root hardening is a step-25 item.
FROM python:3.12-slim

ENV PATH="/root/.local/bin:${PATH}"

# Slither + solc-select. A default solc is pre-installed so analysis works
# offline under --network none. Contracts whose pragma needs another solc that
# isn't installed will fail compilation -> SLITHER_COMPILATION_FAILED (expected).
RUN pip install --no-cache-dir --user slither-analyzer solc-select \
    && solc-select install 0.8.20 \
    && solc-select use 0.8.20

WORKDIR /scan

# The runner always passes the slither command explicitly.
ENTRYPOINT []
CMD ["slither", "--version"]
