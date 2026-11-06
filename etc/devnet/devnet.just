# Local all-Zig devnet. Owned by the batcher-devnet lane (see docs/lanes/batcher-devnet.md).
set working-directory := '../..'

default:
    @just --justfile {{ source_file() }} --list

# Start the devnet: L1 dev chain, L2 sequencer, batcher, verifier
up:
    etc/devnet/devnet.sh up

# Stop all devnet processes
down:
    etc/devnet/devnet.sh down

# Show heads of every node
status:
    etc/devnet/devnet.sh status

# Tail logs
logs:
    etc/devnet/devnet.sh logs

# Stop, wipe .devnet/, start fresh
reset:
    etc/devnet/devnet.sh down
    rm -rf .devnet
    etc/devnet/devnet.sh up

# End-to-end check: L2 tx sequenced, batched to L1, derived by verifier
smoke:
    etc/devnet/devnet.sh smoke

# The same devnet in Docker (etc/docker/docker-compose.yml); `smoke` checks it too
docker-up:
    etc/devnet/devnet.sh down
    docker compose -f etc/docker/docker-compose.yml up -d --build

# Stop and remove the Docker devnet
docker-down:
    docker compose -f etc/docker/docker-compose.yml down
