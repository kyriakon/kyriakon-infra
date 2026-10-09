#!/bin/ksh
# Simulate the strike arithmetic and case-match exactly as abuse-monitor.sh does.
state=$(mktemp)
strike() {  # $1=zone $2=reason
	zone="$1"; reason="$2"
	dnsbl_seen=$(cat "$state" 2>/dev/null || true)
	case "$dnsbl_seen" in
	"$zone:$reason:"*) dnsbl_strikes=$((${dnsbl_seen##*:} + 1)) ;;
	*) dnsbl_strikes=1 ;;
	esac
	printf '%s\n' "$zone:$reason:$dnsbl_strikes" > "$state"
	if [ "$dnsbl_strikes" -eq 3 ]; then printf 'ALERT %s %s (strike %s)\n' "$zone" "$reason" "$dnsbl_strikes"; else printf 'quiet %s %s (strike %s)\n' "$zone" "$reason" "$dnsbl_strikes"; fi
}
reset() { rm -f "$state"; }
echo "-- old-format file on disk --"
printf 'bl.spamcop.net:servfail\n' > "$state"; strike bl.spamcop.net servfail
echo "-- persistent downgrade, same zone+reason (should alert on 3rd only) --"
reset; strike bl.spamcop.net servfail; strike bl.spamcop.net servfail; strike bl.spamcop.net servfail; strike bl.spamcop.net servfail
echo "-- operator's flicker: silent, clean(strongest=reset), silent ... --"
reset; strike bl.spamcop.net no-answer; reset; strike bl.spamcop.net no-answer; reset; strike bl.spamcop.net no-answer
echo "-- reason changes mid-episode --"
reset; strike bl.spamcop.net servfail; strike bl.spamcop.net no-answer; strike bl.spamcop.net servfail
echo "-- zone changes mid-episode --"
reset; strike bl.spamcop.net no-answer; strike all.s5h.net no-answer; strike bl.spamcop.net no-answer
rm -f "$state"
