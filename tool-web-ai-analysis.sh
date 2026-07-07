#!/bin/bash
scope="${BIRD_SCOPE_DOMAIN:-$(head -n 1 OUT-WEB-BIRD/.current-scope 2>/dev/null)}";[ -n "$scope" ] && python3 bird-ai-analysis.py --out-dir OUT-WEB-BIRD --dashboard-dir dashboard --scope-domain "$scope" "${@}"
