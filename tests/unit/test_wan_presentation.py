from vysion.api.app import _preview_payload
from vysion.audit.parser import FortiGateParser


def test_preview_lists_all_sdwan_zones_and_all_member_interfaces() -> None:
    configuration = FortiGateParser().parse(
        """config system interface
    edit "wan1"
        set role wan
    next
    edit "wan2"
        set role wan
    next
    edit "mpls1"
        set role wan
    next
end
config system sdwan
    set status enable
    config zone
        edit "Z-INTERNET"
        next
        edit "Z-INTERSITE"
        next
        edit "Z-EMPTY"
        next
    end
    config members
        edit 1
            set interface "wan1"
            set zone "Z-INTERNET"
        next
        edit 2
            set interface "wan2"
            set zone "Z-INTERNET"
        next
        edit 3
            set interface "mpls1"
            set zone "Z-INTERSITE"
        next
    end
end
"""
    )

    preview = _preview_payload(configuration)

    assert preview["sdwan_zones"] == [
        {"name": "Z-INTERNET", "interfaces": ["wan1", "wan2"], "proof_state": "proven"},
        {"name": "Z-INTERSITE", "interfaces": ["mpls1"], "proof_state": "proven"},
        {"name": "Z-EMPTY", "interfaces": [], "proof_state": "unknown"},
    ]
    assert preview["sdwan_members"] == [
        {"name": "wan1", "zones": ["Z-INTERNET"]},
        {"name": "wan2", "zones": ["Z-INTERNET"]},
        {"name": "mpls1", "zones": ["Z-INTERSITE"]},
    ]
