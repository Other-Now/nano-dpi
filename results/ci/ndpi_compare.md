# nanodpi vs nDPI expected output
capture files with an nDPI .out: 683; with >=1 labelled HTTP/TLS/DNS/QUIC flow: 242
nanodpi non-zero exits: 0

## mode: reasm

| L7 | nDPI flows with host | same_host | different_host | no_host | flow_not_found | agreement |
|---|---:|---:|---:|---:|---:|---:|
| HTTP | 1161 | 1159 | 1 | 1 | 0 | 99.8% |
| TLS | 791 | 783 | 0 | 5 | 3 | 99.0% |
| DNS | 492 | 450 | 35 | 5 | 2 | 91.5% |
| QUIC | 167 | 137 | 0 | 28 | 2 | 82.0% |
| all | 2611 | 2529 | 36 | 39 | 7 | 96.9% |

L7 label agreement on flows found: {'same_l7': 2565, 'other_l7': 39}

## mode: no_reasm

| L7 | nDPI flows with host | same_host | different_host | no_host | flow_not_found | agreement |
|---|---:|---:|---:|---:|---:|---:|
| HTTP | 1161 | 1155 | 1 | 5 | 0 | 99.5% |
| TLS | 791 | 773 | 0 | 15 | 3 | 97.7% |
| DNS | 492 | 448 | 35 | 7 | 2 | 91.1% |
| QUIC | 167 | 137 | 0 | 28 | 2 | 82.0% |
| all | 2611 | 2513 | 36 | 55 | 7 | 96.2% |

L7 label agreement on flows found: {'same_l7': 2559, 'other_l7': 45}

flows where only the reassembling engine got the name: 16 (reasm_only_wins.csv)
