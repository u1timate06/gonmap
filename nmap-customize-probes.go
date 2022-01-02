package gonmap

var NMAP_CUSTOMIZE_PROBES = `
##############################NEXT PROBE##############################
Probe TCP DECRPC q|\x05\0\x0B\x03\x10\0\0\0\x48\0\0\0\x01\0\0\0\xB8\x10\xB8\x10\0\0\0\0\x01\0\0\0\0\0\x01\0\xC4\xFE\xFC\x99\x60\x52\x1B\x10\xBB\xCB\0\xAA\0\x21\x34\x7A\0\0\0\0\x04\x5D\x88\x8A\xEB\x1C\xC9\x11\x9F\xE8\x08\0\x2B\x10\x48\x60\x02\0\0\0\x|
rarity 8
ports 135

match decrpc m|^.*135.*$| p/IPC/
`
