#!/bin/ksh
state=$(mktemp -d)
ip=192.0.2.10
dnsbl_zones="zen.spamhaus.org bl.spamcop.net all.s5h.net dnsbl.dronebl.org"
alert() { echo "ALERT <$1>"; }
consume() {
 verdict="$1"
		zone=$(printf '%s' "$verdict" | awk '{print $2}')
		# shellcheck disable=SC2154 # dnsbl_zones is set by lib.sh when sourced
		strongest=${dnsbl_zones%% *}
		# Why the strongest list was skipped decides what to say, and lib.sh
		# records it in the verdict. A zone that answered with a refusal is a
		# policy aimed at this resolver and nothing here is broken; a zone that
		# said nothing at all is this box's DNS. Sending the reader to check
		# unbound for the first is what this alert did on 2026-10-03, to an
		# operator whose unbound was answering everything else.
		skipped=$(printf '%s' "$verdict" | sed -n 's/.*\[skipped: //p' | sed 's/\]$//')
		reason=${skipped#*=}
		reason=${reason%% *}
		if [ "$zone" != "$strongest" ]; then
			# A zone that is slow rather than down gives one downgrade and then a
			# clean run, and under a once-per-change rule that is an alert every
			# other run. That is what reached the operator every few hours on
			# 2026-10-09. A downgrade is reported only once it has held for three
			# consecutive runs, three quarters of an hour, and the count resets the
			# moment the zone gives a verdict again.
			dnsbl_seen=$(cat "$state/dnsbl.downgraded" 2>/dev/null || true)
			case "$dnsbl_seen" in
			"$zone:$reason:"*) dnsbl_strikes=$((${dnsbl_seen##*:} + 1)) ;;
			*) dnsbl_strikes=1 ;;
			esac
			printf '%s\n' "$zone:$reason:$dnsbl_strikes" > "$state/dnsbl.downgraded"
			if [ "$dnsbl_strikes" -eq 3 ]; then
				case "$reason" in
				refused)
					# A refusal is a policy aimed at this resolver, and nothing on
					# this box is broken. Spamhaus refuses a shared resolver with
					# its control answer, which is what the second query gets; the
					# check asks 127.0.0.1 first, so a refusal means the box's own
					# resolver did not answer and the fallback was refused.
					alert "blocklist downgraded" "$ip is clean on $zone only: $strongest refused the query rather than giving a verdict, which is Spamhaus's answer to a resolver it will not serve. Nothing is listed on $strongest as far as this check can tell, and the runbook's blocklist section reads this one"
					;;
				servfail)
					# QNAME minimisation is already off in the tracked config, so a
					# servfail is usually a lookup that timed out rather than a
					# setting to change. The runbook's section says how to tell.
					alert "blocklist downgraded" "$ip is clean on $zone only: $strongest gave servfail rather than a verdict. Nothing is listed on $strongest as far as this check can tell. The tracked config sets the QNAME minimisation line to no, so if that has been deployed the likely cause is a lookup that timed out, and the runbook's blocklist section says how to tell"
					;;
				*)
					# Something said nothing at all, which has two causes and only one
					# of them is this box's DNS. Either unbound is not answering, or it
					# was not answering in time and the query went to the system
					# resolver, which Spamhaus ignores by design: a silent zen through
					# that fallback is expected, not a finding. The old advice named
					# only the second and blamed a reboot, which sent the operator to
					# a healthy resolver on 2026-10-05 and told them the next run
					# would be clean when it was not.
					alert "blocklist downgraded" "$ip is clean on $zone only; $strongest did not answer for three runs in a row. The strongest list is the one that matters for deliverability, so a listing there would go unnoticed. Either the zone is slow enough that the look-up times out, or unbound is not answering and the query went to the system resolver, which Spamhaus ignores by design. Run check-hygiene.sh by hand and rcctl check unbound, and the runbook's blocklist section says how to tell the two apart"
					;;
				esac
			fi
		else
			rm -f "$state/dnsbl.downgraded"
		fi
}
echo "== flicker: silent, clean-from-zen, silent =="
consume "clean bl.spamcop.net [skipped: zen.spamhaus.org=no-answer]"
consume "clean zen.spamhaus.org"
echo "  after strongest clean, file=[$(cat "$state/dnsbl.downgraded" 2>/dev/null)] (empty expected)"
consume "clean bl.spamcop.net [skipped: zen.spamhaus.org=no-answer]"
echo "  after flicker, file=[$(cat "$state/dnsbl.downgraded" 2>/dev/null)]"
echo "== persistent silent x3 =="
consume "clean bl.spamcop.net [skipped: zen.spamhaus.org=no-answer]"
consume "clean bl.spamcop.net [skipped: zen.spamhaus.org=no-answer]"
consume "clean bl.spamcop.net [skipped: zen.spamhaus.org=no-answer]"
echo "  file=[$(cat "$state/dnsbl.downgraded" 2>/dev/null)]"
echo "== strongest clean =="
consume "clean zen.spamhaus.org"
echo "  file=[$(cat "$state/dnsbl.downgraded" 2>/dev/null)] (empty expected)"
