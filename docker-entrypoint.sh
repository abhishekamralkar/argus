#!/bin/sh
# Entrypoint for the bundled argus+Ollama image.
# Starts ollama serve in the background, waits for it to be ready,
# then pulls required models (if not already cached), then runs argus.

set -e

OLLAMA_HOST="${OLLAMA_HOST:-http://localhost:11434}"

# Start Ollama in the background
ollama serve &
OLLAMA_PID=$!

# Wait up to 30 seconds for Ollama to accept connections.
i=0
until curl -sf "${OLLAMA_HOST}/api/tags" > /dev/null 2>&1; do
    i=$((i+1))
    if [ $i -ge 30 ]; then
        echo "argus: timed out waiting for Ollama to start" >&2
        kill "$OLLAMA_PID" 2>/dev/null
        exit 1
    fi
    sleep 1
done

# Pull models if not already present (skipped when ARGUS_SKIP_PULL=1).
if [ "${ARGUS_SKIP_PULL:-0}" != "1" ]; then
    EMBED_MODEL="${ARGUS_EMBED_MODEL:-nomic-embed-text}"
    LLM_MODEL="${ARGUS_LLM_MODEL:-gpt-oss:20b}"

    for model in "$EMBED_MODEL" "$LLM_MODEL"; do
        if ! ollama list 2>/dev/null | grep -q "^${model}"; then
            echo "argus: pulling model ${model} ..."
            ollama pull "$model" || echo "argus: warning: could not pull ${model}" >&2
        fi
    done
fi

# Hand off to argus.
exec argus "$@"
