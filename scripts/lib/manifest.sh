#!/bin/ksh
# manifest.sh: the install-set.tsv queries every reader shares. Sourced by
# scripts/lib.sh.
#
# scripts/install-set.tsv is the box manifest, one row per installed file:
#
#   script        the file in scripts/, or a compiled binary for a binary row
#   destination   where it lands, or - for a source read from the checkout
#   schedule      the five cron fields, or - when nothing schedules it
#   args          the arguments the cron line passes, or omitted
#   deploy_route  the deploys (and manual steps) a change to it needs,
#                 comma separated: mail, control, relayd, nsd, cron, env, pf,
#                 doas, or none
#   installed_name the name at the destination, or - when it keeps its own
#   status        active (default when the column is absent) or retired
#
# A retired row is an uninstall step: the destination must not carry the file,
# and the deploy named in its route removes it. A script installed in two
# places has one row per place.

# manifest_rows <table> [<script>]: active rows, tab-separated, one per line.
manifest_rows() {
	typeset table="$1" name="${2:-}"
	[ -f "$table" ] || {
		printf 'manifest_rows: no table at %s\n' "$table" >&2
		return 1
	}
	awk -F'\t' -v n="$name" '
		!/^#/ && NF >= 3 && (n == "" || $1 == n) {
			status = ($7 == "" ? "active" : $7)
			if (status == "active") print
		}' "$table"
}

# manifest_has <table> <script>: true when it has a row, active or retired.
manifest_has() {
	typeset table="$1" name="$2"
	[ -f "$table" ] || {
		printf 'manifest_has: no table at %s\n' "$table" >&2
		return 1
	}
	awk -F'\t' -v n="$name" '!/^#/ && NF >= 3 && $1 == n { found = 1 } END { exit !found }' "$table"
}

# manifest_routes <table> <script>: each deploy/manual token from the active
# rows, one per line. Empty when the rows name none.
manifest_routes() {
	typeset table="$1" name="$2" rows
	rows=$(manifest_rows "$table" "$name") || return 1
	[ -n "$rows" ] || return 0
	printf '%s\n' "$rows" |
		awk -F'\t' '$5 != "" && $5 != "-" { n = split($5, a, ","); for (i = 1; i <= n; i++) print a[i] }' |
		sort -u
}

# manifest_retired_routes <table> <script>: the same for retired rows, so a
# deleted script still plans the deploy that removes its installed copy.
manifest_retired_routes() {
	typeset table="$1" name="$2"
	[ -f "$table" ] || return 1
	awk -F'\t' -v n="$name" '
		!/^#/ && NF >= 3 && $1 == n && $7 == "retired" && $5 != "" && $5 != "-" {
			k = split($5, a, ","); for (i = 1; i <= k; i++) print a[i]
		}' "$table" | sort -u
}

# manifest_active_names <table> <destination>: active script names for one
# destination, which is the old install_rows contract.
manifest_active_names() {
	typeset rows
	rows=$(manifest_rows "$1") || return 1
	[ -n "$rows" ] || return 0
	printf '%s\n' "$rows" | awk -F'\t' -v d="$2" '$2 == d { print $1 }'
}

# manifest_targets <table> <destination>: "script<TAB>installed-name" for the
# active rows, so a rename lives in the table rather than in each deploy.
manifest_targets() {
	typeset rows
	rows=$(manifest_rows "$1") || return 1
	[ -n "$rows" ] || return 0
	printf '%s\n' "$rows" | awk -F'\t' -v d="$2" '$2 == d {
		name = ($6 == "" || $6 == "-" ? $1 : $6)
		print $1 "\t" name
	}'
}

# manifest_targets_route <table> <destination> <route>: the same, restricted to
# rows whose deploy_route names <route>. A destination can hold files from two
# deploys (the login checker beside the mail filter), and the route is what says
# which one installs it.
manifest_targets_route() {
	typeset rows
	rows=$(manifest_rows "$1") || return 1
	[ -n "$rows" ] || return 0
	printf '%s\n' "$rows" | awk -F'\t' -v d="$2" -v r="$3" '
		$2 != d { next }
		route = "," $5 ","
		if (index(route, "," r ",") == 0) next
		name = ($6 == "" || $6 == "-" ? $1 : $6)
		print $1 "\t" name
	}'
}

# manifest_retired_names <table> <destination>: installed names the retired
# rows say must be absent there.
manifest_retired_names() {
	typeset table="$1" destination="$2"
	[ -f "$table" ] || return 1
	awk -F'\t' -v d="$destination" '
		!/^#/ && NF >= 3 && $2 == d && $7 == "retired" {
			name = ($6 == "" || $6 == "-" ? $1 : $6)
			print name
		}' "$table"
}

# manifest_installed_name <table> <script> <destination>: the one name a row
# installs under that destination.
manifest_installed_name() {
	typeset table="$1" script="$2" destination="$3"
	manifest_rows "$table" "$script" | awk -F'\t' -v d="$destination" '$2 == d {
		print ($6 == "" || $6 == "-" ? $1 : $6); exit
	}'
}
