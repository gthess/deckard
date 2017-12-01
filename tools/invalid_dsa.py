# Returns 1 if there is a DNSSEC DSA signature which is not 41 bytes long. 0 otherwise.

import os
import sys
sys.path.insert(0,'..')
import pydnstest.scenario
import base64

test = sys.argv[1]

dsakeys = []
_, config = pydnstest.scenario.parse_file(os.path.realpath(test))
for conf in config:
    if conf[0] == "trust-anchor":
        conf[1] = conf[1][1:-1]
        trust_anchor = conf[1].split()
        for i, word in enumerate(trust_anchor):
            if word == "DS":
                algorithm = trust_anchor[i+2]
                if algorithm == "3" or algorithm == "DSA":
                    dsakeys.append(trust_anchor[i+1])
aug = pydnstest.augwrap.AugeasWrapper(
        confpath=os.path.realpath(test), lens='Deckard', loadpath="../pydnstest")
node = aug.tree

for entry in node.match("/scenario/range/entry"):
    records = list(entry.match("/section/answer/record"))
    records.extend(list(entry.match("/section/authority/record")))
    records.extend(list(entry.match("/section/additional/record")))

    for record in records:
        if record["/type"].value == "DS":
            if record["/data"].value[1] == "3" or record["/data"].value[1] == "DSA":
                dsakeys.append(Key(record["/data"].value[2], record["/domain"].value))

for key in dsakeys:
    # Find records which need to be resigned
    zone_records = []
    for entry in node.match("/scenario/range/entry"):
        records = list(entry.match("/section/answer/record"))
        records.extend(list(entry.match("/section/authority/record")))
        records.extend(list(entry.match("/section/additional/record")))

        for record in records:
            if record["/type"].value == "RRSIG":
                rrsig_data = record["/data"].value.split()
                if rrsig_data[6] == key and len(base64.b64decode(rrsig_data[8])) != 41:
                    sys.exit(1)
sys.exit(0)
