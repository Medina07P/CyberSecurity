#!/bin/bash
# PCAP ANALYZER — indicadores, no vulnerabilidades probadas.
# Uso: ./pcap_analyzer.sh <PCAP_FILE>
# Ejemplo: ./pcap_analyzer.sh captura.pcap
LIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../00_Config/lib" && pwd)"
source "$LIB_DIR/forensics_volatility.bash" || exit 2
[[ $# = 1 ]] || { printf 'Uso: ./pcap_analyzer.sh <PCAP_FILE>\n' >&2; exit 2; }
input=$1
[[ $input = /* ]] || input="$PWD/$input"
for tool in capinfos tshark sort grep; do forensics_require "$tool" || exit 2; done
forensics_offline_validate "$input" || exit 2
printf 'Se copiará y verificará íntegramente la entrada; requiere espacio y tiempo.\n' >&2
forensics_begin pcap offline || exit $?
work=$(forensics_stage "$input") || { forensics_finish; exit 1; }
forensics_adapter_private_home || { forensics_finish; exit 1; }
forensics_capture capinfos capinfos "$work"
rc=$?; state=COMPLETADO; coverage=pcap_validated
if (( rc == 0 )) && ! forensics_adapter_inspect capinfo "$FORENSICS_STEP_OUT"; then
    state=NO_EVALUABLE; coverage=pcap_format_unrecognized
fi
forensics_adapter_complete capinfos "$rc" "$state" "$coverage" || { forensics_finish; exit 1; }
if (( rc != 0 )) || [[ $state != COMPLETADO ]]; then forensics_finish; exit 1; fi

# -z protocols is not a tshark statistic. Require advertised io,phs and conv.
forensics_capture tshark_version tshark --version
rc=$?; version_ok=0
if (( rc == 0 )) && forensics_adapter_inspect tshark_version "$FORENSICS_STEP_OUT"; then version_ok=1; fi
forensics_adapter_complete tshark_version "$rc" || { forensics_finish; exit 1; }
forensics_capture tshark_help tshark -z help
rc=$?; stats=0
if (( rc == 0 && version_ok == 1 )) && forensics_adapter_inspect stats "$FORENSICS_STEP_OUT" "$FORENSICS_STEP_ERR"; then stats=1; fi
forensics_adapter_complete tshark_help "$rc" || { forensics_finish; exit 1; }
pcap_sorted() { sort -u -- "$1"; }
pcap_sensitive() {
    # Producer is already fully captured and sealed. grep rc1 = no indicators.
    local rc
    grep -E 'pass|user|login' -- "$1"
    rc=$?
    (( rc <= 1 )) || return "$rc"
    return 0
}
for name in protocols conversations_tcp conversations_udp; do
    if (( stats == 0 )); then
        forensics_adapter_noeval "$name" tshark_statistics_unsupported || { forensics_finish; exit 1; }
        continue
    fi
    case $name in protocols) statistic=io,phs;; conversations_tcp) statistic=conv,tcp;; conversations_udp) statistic=conv,udp;; esac
    forensics_capture "$name" tshark -n -r "$work" -q -z "$statistic"
    rc=$?
    forensics_adapter_complete "$name" "$rc" || { forensics_finish; exit 1; }
done
for name in dns_queries http_requests credentials files; do
    case $name in
        dns_queries) forensics_capture "raw_$name" tshark -n -r "$work" -Y 'dns.flags.response==0' -T fields -e dns.qry.name;;
        http_requests) forensics_capture "raw_$name" tshark -n -r "$work" -Y http.request -T fields -e http.request.uri -e http.host;;
        credentials) forensics_capture "raw_$name" tshark -n -r "$work" -Y 'http.request.method == "POST"' -T fields -e http.request.uri -e http.host -e http.request.uri.query;;
        files) forensics_capture "$name" tshark -n -r "$work" -Y http.response -T fields -e http.file_data -e http.content_type;;
    esac
    rc=$?
    if [[ $name = files ]]; then
        forensics_adapter_complete "$name" "$rc" || { forensics_finish; exit 1; }
        continue
    fi
    raw=$FORENSICS_STEP_OUT
    forensics_adapter_complete "raw_$name" "$rc" || { forensics_finish; exit 1; }
    if (( rc != 0 )); then
        forensics_adapter_noeval "$name" producer_failed || { forensics_finish; exit 1; }
        continue
    fi
    if [[ $name = credentials ]]; then forensics_capture "$name" pcap_sensitive "$raw"
    else forensics_capture "$name" pcap_sorted "$raw"; fi
    rc=$?
    forensics_adapter_complete "$name" "$rc" || { forensics_finish; exit 1; }
done
forensics_finish
exit $?
