#!/usr/bin/env python3
"""Generate the octet-semantic-binding-v4 golden vectors (vectors.json).

Independent of the Rust verifier: it builds each v4 preimage from the frozen v3
vectors' preimage bytes, so a v4 vector can only change if the v3 contract or
the v4 suffix changes.

    v4 = "octet-semantic-binding-v4" || v3_preimage[len("octet-semantic-binding-v3"):]
         || u32be(len(lid)) || lid

Run from the repository root:

    python3 -I test-vectors/semantic-binding-v4/generate.py > test-vectors/semantic-binding-v4/vectors.json
"""

import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
V3 = os.path.join(HERE, "..", "semantic-binding-v3", "vectors.json")

DOMAIN_V3 = b"octet-semantic-binding-v3"
DOMAIN_V4 = b"octet-semantic-binding-v4"

# Synthetic licence ids: canonical lowercase hyphenated UUIDs, not real licences.
LICENSE_A = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
LICENSE_B = "1b4e28ba-2fa1-41d2-883f-0016d3cca427"


def v4_preimage(v3_hex: str, lid: str) -> bytes:
    v3 = bytes.fromhex(v3_hex)
    assert v3.startswith(DOMAIN_V3)
    raw = lid.encode("utf-8")
    return DOMAIN_V4 + v3[len(DOMAIN_V3):] + struct.pack(">I", len(raw)) + raw


def main() -> None:
    with open(V3) as f:
        v3 = {v["name"]: v for v in json.load(f)["vectors"]}

    def signed_v4(base: str, lid: str) -> dict:
        pre = v4_preimage(v3[base]["preimage_hex"], lid)
        return {
            "domain": DOMAIN_V4.decode(),
            "committed_license_id": lid,
            "preimage_hex": pre.hex(),
            "stage_hash_hex": hashlib.sha256(pre).hexdigest(),
        }

    def signed_v3(base: str) -> dict:
        return {
            "domain": DOMAIN_V3.decode(),
            "committed_license_id": None,
            "preimage_hex": v3[base]["preimage_hex"],
            "stage_hash_hex": v3[base]["stage_hash_hex"],
        }

    def vector(name, base, signed, presented, expect, note):
        return {
            "name": name,
            "note": note,
            "base_v3_vector": base,
            "input": v3[base]["input"],
            "query_region": v3[base]["query_region"],
            "signed": signed,
            "presented_license_id": presented,
            "expect": expect,
        }

    vectors = [
        vector("v4_disc_inside", "disc_inside", signed_v4("disc_inside", LICENSE_A),
               LICENSE_A, "pass", "a disc query, INSIDE, committing licence A"),
        vector("v4_country_outside", "country_at_claim_gb", signed_v4("country_at_claim_gb", LICENSE_B),
               LICENSE_B, "pass", "a country AT query with a GB claim, OUTSIDE, committing licence B"),
        vector("v4_no_query", "no_query", signed_v4("no_query", LICENSE_A),
               LICENSE_A, "pass", "a background proof: no query (q_type 0, field 18 absent), committing licence A"),
        vector("tamper_license_edited", "disc_inside", signed_v4("disc_inside", LICENSE_A),
               LICENSE_B, "fail", "signed for licence A, field 21 edited to licence B after signing"),
        vector("tamper_license_removed", "disc_inside", signed_v4("disc_inside", LICENSE_A),
               None, "fail", "signed for licence A, field 21 removed after signing; v3 does not match either"),
        vector("tamper_license_on_v3", "disc_inside", signed_v3("disc_inside"),
               LICENSE_A, "fail", "a v3 proof with field 21 added: the licence was never signed"),
    ]

    doc = {
        "note": "octet-semantic-binding-v4 (committed licence) cross-repo golden vectors, "
                "derived from the frozen v3 vectors by generate.py. See README.md.",
        "domain": DOMAIN_V4.decode(),
        "vectors": vectors,
    }
    json.dump(doc, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
