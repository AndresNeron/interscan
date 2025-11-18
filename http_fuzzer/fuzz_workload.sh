#!/usr/bin/env bash
set -euo pipefail

# Arguments
HOSTS_LIST="$1"         # samples/localhost
ENDPOINT_WORDLIST="$2"  # wordlists/php_scripts.txt
PARAM_WORDLIST="$3"     # wordlists/params.txt
PAYLOAD_LIST="$4"       # payloads/os.txt

OUTDIR="results"
VULNERABLE_ENDPOINTS="${OUTDIR}/vulnerable_endpoints.txt"

mkdir -p "$OUTDIR"

# Iterate over hosts listed in HOSTS_LIST file
while IFS= read -r HOST || [ -n "${HOST:-}" ]; do
    [[ -z "$HOST" ]] && continue   # skip empty lines

    BASE="http://$HOST"
    EXISTING_ENDPOINTS="${OUTDIR}/${HOST}_endpoints.txt"

    echo
    echo "[*] Scanning host: $HOST"
    echo "[*] Running ffuf to discover endpoints..."

    FFUF_OUT="${OUTDIR}/${HOST}_endpoints.ffuf"
    CLEAN="${OUTDIR}/${HOST}_endpoints.clean"

    # Ffuf run
    ffuf -u "${BASE}/FUZZ" -w "${ENDPOINT_WORDLIST}" -e .php -t 100 -mc 200 \
        | tee "${FFUF_OUT}"

    # Clean ffuf output
    sed -r 's/\x1B\[[0-9;]*[mK]//g' "${FFUF_OUT}" \
        | awk '{print $1}' \
        | tr -d '\r' \
        | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
        | grep -v '^$' \
        | sort -u > "${CLEAN}" || true

    echo "[*] Found $(wc -l < "${CLEAN}") endpoints for $HOST. Listing:"
    sed "s/^/http:\/\/$HOST\//g" "${CLEAN}" | tee "$EXISTING_ENDPOINTS"

    echo
    echo "[*] Testing endpoints on $HOST..."

    # Loop through discovered endpoints
    while IFS= read -r raw_php_script || [ -n "${raw_php_script:-}" ]; do

        # Normalize entry
        php_script="$(printf '%s' "$raw_php_script" \
                        | sed -r 's/\x1B\[[0-9;]*[mK]//g' \
                        | tr -d '\r' \
                        | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"

        [[ -z "$php_script" ]] && continue
        php_script="${php_script#/}"   # remove leading "/"

        # Loop through parameters
        while IFS= read -r param || [ -n "${param:-}" ]; do
            # Loop through payloads
            while IFS= read -r payload || [ -n "${payload:-}" ]; do
                [[ -z "$payload" ]] && continue

                url=$(printf '%s/%s?%s=%s' "$BASE" "$php_script" "$param" "$payload")


                resp=$(curl -s --max-time 10 "$url" || true)

                # Print if vulnerable (your signature check)
                if printf '%s' "$resp" | grep -q 'NAME'; then
					echo "----------------------------------------"
					echo "$url"
                    echo "$resp"
                    echo "$url" >> "$VULNERABLE_ENDPOINTS"
                fi

                sleep 0.02

            done < "$PAYLOAD_LIST"

        done < "$PARAM_WORDLIST"

    done < "$CLEAN"

done < "$HOSTS_LIST"

echo
echo "[*] Scan completed."
echo "[*] Vulnerable endpoints saved in: $VULNERABLE_ENDPOINTS"
