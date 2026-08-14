#!/usr/bin/env sh
# merge-domain-check.sh — precondition for merge-completing deny rules.
#
# Purpose (flotilla#551 / authority-domain Track A):
#   A seat with .gatekeeper/lead may merge ONLY within its authority domain.
#   CWD lead alone must not authorize `gh pr merge --repo OTHER`.
#
# Invoked as a gatekeeper precondition. Always exits 0 and prints either OK or
# one factual "Merge denied:" diagnostic on stdout. Deny rules match the
# diagnostic; OK skips the rule so the standing clean-gates ALLOW can fire.
# Never exit non-zero on a deny
# path — a failed precondition *skips* the deny rule (fail-open).
#
# Environment (set by the engine for every precondition):
#   GATEKEEPER_INPUT  — the (heredoc-stripped) tool input under evaluation
#
# Domain resolution (P0, remote-discovery; Track C can supersede via file):
#   1. If <cwd>/.gatekeeper/domain exists: each non-empty, non-# line is an
#      allowed owner/name (case-insensitive). First line is primary.
#      flotilla-dev's roster `primary_repo` should materialize this file.
#   2. Else: owner/name parsed from `git remote get-url origin`.
#
# Deny arms (matched by precondition_match = '^Merge denied:'):
#   not_lead          — no .gatekeeper/lead in the effective cwd
#   domain_mismatch   — explicit target repo is outside the resolved domain
#   target_unresolved — command names a target we cannot extract → fail-closed
#   domain_unresolved — explicit target present but no domain resolves
#   OK                — lead + (implicit cwd target, or target in domain)
#
# Explicit targets recognized:
#   gh pr merge ... --repo OWNER/REPO | -R OWNER/REPO | --repo=OWNER/REPO
#   gh api ... repos/OWNER/REPO/pulls/N/merge ...
#   curl .../repos/OWNER/REPO/pulls/N/merge ...
#   gh api ... graphql ... mergePullRequest ... (no reliable repo → UNPARSEABLE)

set -eu

cmd=${GATEKEEPER_INPUT-}
effective_cwd=$(pwd -P)
lead_marker=$effective_cwd/.gatekeeper/lead
domain_marker=$effective_cwd/.gatekeeper/domain

normalize() {
	printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

is_owner_repo() {
	# exactly one slash, non-empty sides, safe chars
	case $1 in
	*/*/*) return 1 ;;
	[a-zA-Z0-9_.-]*/[a-zA-Z0-9_.-]*) return 0 ;;
	*) return 1 ;;
	esac
}

remote_to_owner_repo() {
	url=$1
	printf '%s' "$url" | sed -E \
		-e 's#^git@[^:]+:##' \
		-e 's#^ssh://[^/]+/##' \
		-e 's#^https?://[^/]+/##' \
		-e 's#\.git$##' \
		-e 's#/$##'
}

# DOMAIN_LIST: newline-separated normalized owner/name entries.
# DOMAIN_PRIMARY: first entry (may be empty).
DOMAIN_LIST=
DOMAIN_PRIMARY=
DOMAIN_SOURCE=

load_domain() {
	DOMAIN_LIST=
	DOMAIN_PRIMARY=
	DOMAIN_SOURCE=
	if [ -f .gatekeeper/domain ]; then
		DOMAIN_SOURCE=$domain_marker
		while IFS= read -r line || [ -n "$line" ]; do
			# strip comments and whitespace
			line=$(printf '%s' "$line" | sed -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
			[ -z "$line" ] && continue
			if is_owner_repo "$line"; then
				n=$(normalize "$line")
				if [ -z "$DOMAIN_PRIMARY" ]; then
					DOMAIN_PRIMARY=$n
				fi
				DOMAIN_LIST="${DOMAIN_LIST}${n}
"
			fi
		done < .gatekeeper/domain
		return 0
	fi
	url=$(git remote get-url origin 2>/dev/null || true)
	if [ -n "$url" ]; then
		raw=$(remote_to_owner_repo "$url")
		if is_owner_repo "$raw"; then
			n=$(normalize "$raw")
			DOMAIN_PRIMARY=$n
			DOMAIN_LIST="${n}
"
			DOMAIN_SOURCE='git remote origin'
		fi
	fi
}

resolved_domains() {
	printf '%s' "$DOMAIN_LIST" | tr '\n' ',' | sed 's/,$//'
}

domain_evidence() {
	if [ -f .gatekeeper/domain ]; then
		printf 'domain_marker=%s (consulted,present); domain_source=%s' "$domain_marker" "$DOMAIN_SOURCE"
	else
		printf 'domain_marker=%s (consulted,absent); domain_source=%s' "$domain_marker" "${DOMAIN_SOURCE:-git remote origin (unresolved)}"
	fi
}

domain_contains() {
	target=$(normalize "$1")
	printf '%s' "$DOMAIN_LIST" | grep -qxF "$target"
}

# Extract explicit target. Prints OWNER/REPO | UNPARSEABLE | empty.
extract_target() {
	# --repo=OWNER/REPO or -R=OWNER/REPO
	eq=$(printf '%s' "$cmd" | sed -nE 's/.*(--repo|-R)=([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+).*/\2/p' | head -n1)
	if [ -n "$eq" ]; then
		printf '%s\n' "$eq"
		return 0
	fi

	# --repo OWNER/REPO or -R OWNER/REPO
	sp=$(printf '%s' "$cmd" | sed -nE 's/.*(--repo|-R)[[:space:]]+([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+).*/\2/p' | head -n1)
	if [ -n "$sp" ]; then
		printf '%s\n' "$sp"
		return 0
	fi

	# Flag present but value not owner/name → fail-closed
	if printf '%s' "$cmd" | grep -qE '(^|[[:space:]])(--repo|-R)([=[:space:]]|$)'; then
		printf 'UNPARSEABLE\n'
		return 0
	fi

	# gh api / curl: repos/OWNER/REPO/pulls/N/merge
	api=$(printf '%s' "$cmd" | sed -nE 's#.*repos/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/pulls/[0-9]+/merge.*#\1#p' | head -n1)
	if [ -n "$api" ]; then
		printf '%s\n' "$api"
		return 0
	fi

	# pulls/.../merge without repos/OWNER/REPO → fail-closed
	if printf '%s' "$cmd" | grep -qE 'pulls/[0-9]+/merge'; then
		printf 'UNPARSEABLE\n'
		return 0
	fi

	# GraphQL mergePullRequest — no reliable owner/name without a full parser
	if printf '%s' "$cmd" | grep -qiE 'mergePullRequest'; then
		printf 'UNPARSEABLE\n'
		return 0
	fi

	printf '\n'
}

# --- main --------------------------------------------------------------------

if [ ! -f .gatekeeper/lead ]; then
	printf 'Merge denied: arm=not_lead; lead_marker=%s (consulted,absent)\n' "$lead_marker"
	exit 0
fi

load_domain
target=$(extract_target | tr -d '\r' | head -n1)

case $target in
UNPARSEABLE)
	printf 'Merge denied: arm=target_unresolved; requested_target=unresolved; lead_marker=%s (consulted,present); %s\n' "$lead_marker" "$(domain_evidence)"
	exit 0
	;;
"")
	# Implicit target = cwd repo. Lead marker is enough.
	printf 'OK\n'
	exit 0
	;;
esac

if [ -z "$DOMAIN_LIST" ]; then
	printf 'Merge denied: arm=domain_unresolved; resolved_domains=none; requested_target=%s; lead_marker=%s (consulted,present); %s\n' "$(normalize "$target")" "$lead_marker" "$(domain_evidence)"
	exit 0
fi

if domain_contains "$target"; then
	printf 'OK\n'
	exit 0
fi

printf 'Merge denied: arm=domain_mismatch; resolved_domains=%s; requested_target=%s; lead_marker=%s (consulted,present); %s\n' "$(resolved_domains)" "$(normalize "$target")" "$lead_marker" "$(domain_evidence)"
exit 0
