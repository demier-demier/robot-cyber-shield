#!/usr/bin/env python3
"""Create an ephemeral SROS2 keystore with original least-privilege DDS policies."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET


# These are ROS topic names. SROS2/DDS uses the rt/ prefix for topic transport.
ROLE_TOPICS = {
    "planner": {"publish": ["/shield/requests"], "subscribe": []},
    "guard": {
        "publish": ["/robot/cmd_vel", "/robot/telemetry/minimal"],
        "subscribe": ["/shield/requests", "/robot/sensors/raw"],
    },
    "driver": {
        "publish": ["/robot/sensors/raw", "/robot/state"],
        "subscribe": ["/robot/cmd_vel"],
    },
    "analytics": {"publish": [], "subscribe": ["/robot/telemetry/minimal"]},
    "observer": {
        "publish": [],
        "subscribe": ["/robot/state", "/robot/telemetry/minimal"],
    },
    "outsider": {"publish": [], "subscribe": []},
}


def child(parent, name, text=None):
    result = ET.SubElement(parent, name)
    if text is not None:
        result.text = str(text)
    return result


def xml_write(root, path):
    ET.indent(root)
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


def permissions(role: str, domain: int, now: datetime) -> ET.Element:
    root = ET.Element("dds")
    grant = child(child(root, "permissions"), "grant")
    grant.set("name", f"/shield/{role}")
    child(grant, "subject_name", f"CN=/shield/{role}")
    validity = child(grant, "validity")
    fmt = "%Y-%m-%dT%H:%M:%S"
    child(validity, "not_before", (now - timedelta(hours=1)).strftime(fmt))
    child(validity, "not_after", (now + timedelta(days=1)).strftime(fmt))
    rule = child(grant, "allow_rule")
    child(child(rule, "domains"), "id", domain)
    # Jazzy rclpy creates a parameter event publisher even with parameter services
    # disabled. No parameters or services expose application sensor data here.
    for direction in ("publish", "subscribe"):
        topics = child(child(rule, direction), "topics")
        child(topics, "topic", "ros_discovery_info")
        if direction == "publish":
            child(topics, "topic", "rt/parameter_events")
        for topic in ROLE_TOPICS[role][direction]:
            child(topics, "topic", "rt" + topic)
    child(grant, "default", "DENY")
    return root


def governance(domain: int) -> ET.Element:
    root = ET.Element("dds")
    rule = child(child(root, "domain_access_rules"), "domain_rule")
    child(child(rule, "domains"), "id", domain)
    for name, value in {
        "allow_unauthenticated_participants": "false",
        "enable_join_access_control": "true",
        "discovery_protection_kind": "ENCRYPT",
        "liveliness_protection_kind": "ENCRYPT",
        "rtps_protection_kind": "SIGN",
    }.items():
        child(rule, name, value)
    topic_rule = child(child(rule, "topic_access_rules"), "topic_rule")
    for name, value in {
        "topic_expression": "*",
        "enable_discovery_protection": "true",
        "enable_liveliness_protection": "true",
        "enable_read_access_control": "true",
        "enable_write_access_control": "true",
        "metadata_protection_kind": "ENCRYPT",
        "data_protection_kind": "ENCRYPT",
    }.items():
        child(topic_rule, name, value)
    return root


def create_keystore(path: Path, domain: int, observed: Path):
    if path.exists():
        raise ValueError("Keystore must be new; refusing to replace existing identities")
    if not 1 <= domain <= 100:
        raise ValueError("Lab domain must be between 1 and 100")
    os.umask(0o077)
    env = dict(os.environ, ROS_DOMAIN_ID=str(domain))
    subprocess.run(["ros2", "security", "create_keystore", str(path)], env=env,
                   check=True, timeout=30, stdout=subprocess.DEVNULL)
    for role in ROLE_TOPICS:
        subprocess.run(["ros2", "security", "create_enclave", str(path),
                        f"/shield/{role}"], env=env, check=True, timeout=30,
                       stdout=subprocess.DEVNULL)
    xml_write(governance(domain), path / "enclaves/governance.xml")
    now = datetime.now(timezone.utc)
    signed_files = [path / "enclaves/governance.xml"]
    for role in ROLE_TOPICS:
        output = path / f"enclaves/shield/{role}/permissions.xml"
        xml_write(permissions(role, domain, now), output)
        signed_files.append(output)
    # Validate against the schemas installed by SROS2 before signing anything.
    from lxml import etree
    from sros2.policy import get_transport_schema
    for xml in signed_files:
        schema_name = "governance.xsd" if xml.name == "governance.xml" else "permissions.xsd"
        schema = etree.XMLSchema(etree.parse(str(get_transport_schema("dds", schema_name))))
        schema.assertValid(etree.parse(str(xml)))
        subprocess.run([
            "openssl", "smime", "-sign", "-text", "-in", str(xml),
            "-out", str(xml.with_suffix(".p7s")),
            "-signer", str(path / "public/permissions_ca.cert.pem"),
            "-inkey", str(path / "private/permissions_ca.key.pem"),
        ], check=True, timeout=10, stdout=subprocess.DEVNULL)
        # Verify the signature as well; do not copy signed files or keys to evidence.
        subprocess.run([
            "openssl", "smime", "-verify", "-in", str(xml.with_suffix(".p7s")),
            "-CAfile", str(path / "public/permissions_ca.cert.pem"), "-out", os.devnull,
        ], check=True, timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    observed.write_text(json.dumps({
        "schema": "robot-shield-dds-policy/v1", "domain": domain,
        "sros2_xml_schema_validation": True, "smime_signatures_verified": len(signed_files),
        "unauthenticated_participants_allowed": False,
        "default_permissions": "DENY", "data_protection_kind": "ENCRYPT",
        "metadata_protection_kind": "ENCRYPT", "roles": ROLE_TOPICS,
        "packet_capture_performed": False,
    }, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keystore", required=True, type=Path)
    parser.add_argument("--domain", type=int, default=73)
    parser.add_argument("--observed", type=Path, required=True)
    args = parser.parse_args()
    create_keystore(args.keystore, args.domain, args.observed)
