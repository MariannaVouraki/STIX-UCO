import json
import re
from pathlib import Path
from typing import Any, Dict, List

from rdflib import Graph, Namespace, URIRef, Literal, RDF
from rdflib.namespace import XSD

# =========================
# Namespaces
# =========================
EX = Namespace("http://example.org/stix-uco/")
CTI = Namespace("http://example.org/cti-ext/")
CORE = Namespace("https://ontology.unifiedcyberontology.org/uco/core/")
IDENTITY = Namespace("https://ontology.unifiedcyberontology.org/uco/identity/")
ACTION = Namespace("https://ontology.unifiedcyberontology.org/uco/action/")
TOOL = Namespace("https://ontology.unifiedcyberontology.org/uco/tool/")
PATTERN = Namespace("https://ontology.unifiedcyberontology.org/uco/pattern/")
OBSERVABLE = Namespace("https://ontology.unifiedcyberontology.org/uco/observable/")

BASE_DIR = Path(__file__).resolve().parent
INPUT_DIR = BASE_DIR / "01_STIX_EXAMPLES"
OUTPUT_DIR = BASE_DIR / "02_Output" / "ttl"

# =========================
# Type mapping
# =========================
TYPE_MAP = {
    # SDO / SRO / meta
    "bundle": CORE.Bundle,
    "relationship": CORE.Relationship,
    "identity": IDENTITY.Identity,
    "threat-actor": IDENTITY.Organization,
    "attack-pattern": ACTION.ActionPattern,
    "campaign": CORE.Event,
    "intrusion-set": IDENTITY.Identity,
    "malware": TOOL.MaliciousTool,
    "tool": TOOL.Tool,
    "course-of-action": ACTION.Action,
    "report": CORE.Compilation,
    "indicator": PATTERN.Pattern,
    "observed-data": CORE.Event,
    "sighting": CORE.Relationship,
    "marking-definition": CORE.MarkingDefinitionAbstraction,
    "vulnerability": CTI.Vulnerability,
    "note": CTI.Note,
    "opinion": CTI.Opinion,
    "location": IDENTITY.Location,

    # SCO / Observables
    "artifact": OBSERVABLE.Artifact,
    "autonomous-system": OBSERVABLE.AutonomousSystem,
    "directory": OBSERVABLE.Directory,
    "domain-name": OBSERVABLE.DomainName,
    "email-addr": OBSERVABLE.EmailAddress,
    "email-message": OBSERVABLE.EmailMessage,
    "file": OBSERVABLE.File,
    "ipv4-addr": OBSERVABLE.IPv4Address,
    "ipv6-addr": OBSERVABLE.IPv6Address,
    "mac-addr": OBSERVABLE.MACAddress,
    "mutex": OBSERVABLE.Mutex,
    "network-traffic": OBSERVABLE.NetworkTraffic,
    "process": OBSERVABLE.Process,
    "software": OBSERVABLE.Software,
    "url": OBSERVABLE.URL,
    "user-account": OBSERVABLE.UserAccount,
    "windows-registry-key": OBSERVABLE.WindowsRegistryKey,
    "x509-certificate": OBSERVABLE.X509Certificate,
}

# =========================
# Common property mapping
# =========================
COMMON_LITERAL_MAP = {
    "id": CTI.stixId,
    "type": CTI.stixType,
    "name": CORE.name,
    "description": CORE.description,
    "created": CTI.stixCreated,
    "modified": CTI.stixModified,
    "spec_version": CTI.specVersion,
    "revoked": CTI.revoked,
}

LIST_LITERAL_MAP = {
    # Common STIX
    "labels": CTI.label,
    "aliases": CTI.alias,
    "goals": CTI.goal,
    "roles": CTI.role,
    "sectors": CTI.sector,
    "malware_types": CTI.malwareType,
    "tool_types": CTI.toolType,
    "report_types": CTI.reportType,
    "indicator_types": CTI.indicatorType,
    "secondary_motivations": CTI.secondaryMotivation,
    "threat_actor_types": CTI.threatActorType,

    # SCO-ish
    "protocols": OBSERVABLE.protocol,
    "resolves_to_refs": OBSERVABLE.resolvesTo,
    "to_refs": OBSERVABLE.to,
    "cc_refs": OBSERVABLE.cc,
    "bcc_refs": OBSERVABLE.bcc,
}

SINGLE_LITERAL_MAP = {
    # Common STIX
    "primary_motivation": CTI.primaryMotivation,
    "sophistication": CTI.sophistication,
    "resource_level": CTI.resourceLevel,
    "objective": CTI.objective,
    "pattern": CTI.stixPattern,
    "pattern_type": CTI.patternType,
    "identity_class": CTI.identityClass,
    "is_family": CTI.isFamily,
    "published": CTI.published,
    "definition_type": CTI.definitionType,
    "count": CTI.sightingCount,
    "number_observed": CTI.numberObserved,
    "first_seen": CTI.firstSeen,
    "last_seen": CTI.lastSeen,
    "first_observed": CTI.firstObserved,
    "last_observed": CTI.lastObserved,
    "valid_from": CTI.validFrom,
    "valid_until": CTI.validUntil,
    "confidence": CTI.confidence,
    "lang": CTI.language,
    "contact_information": CTI.contactInformation,
    "opinion": CTI.opinion,
    "country": CTI.country,
    "administrative_area": CTI.administrativeArea,
    "city": CTI.city,
    "postal_code": CTI.postalCode,
    "street_address": CTI.streetAddress,
    "latitude": CTI.latitude,
    "longitude": CTI.longitude,
    "region": CTI.region,

    # SCO common literals
    "value": OBSERVABLE.value,
    "path": OBSERVABLE.path,
    "name_enc": CTI.nameEncoding,
    "pid": OBSERVABLE.pid,
    "command_line": OBSERVABLE.commandLine,
    "mime_type": OBSERVABLE.mimeType,
    "size": OBSERVABLE.sizeInBytes,
    "is_hidden": OBSERVABLE.isHidden,
    "defanged": CTI.defanged,
    "encoding": CTI.encoding,
    "display_name": CTI.displayName,
    "account_login": OBSERVABLE.accountLogin,
    "account_type": OBSERVABLE.accountType,
    "is_service_account": OBSERVABLE.isServiceAccount,
    "is_privileged": OBSERVABLE.isPrivileged,
    "can_escalate_privs": OBSERVABLE.canEscalatePrivs,
    "credential": OBSERVABLE.credential,
    "service_name": OBSERVABLE.serviceName,
    "start": OBSERVABLE.start,
    "end": OBSERVABLE.end,
    "src_port": OBSERVABLE.srcPort,
    "dst_port": OBSERVABLE.dstPort,
    "src_byte_count": OBSERVABLE.srcByteCount,
    "dst_byte_count": OBSERVABLE.dstByteCount,
    "src_packets": OBSERVABLE.srcPackets,
    "dst_packets": OBSERVABLE.dstPackets,
    "is_active": OBSERVABLE.isActive,
    "key": OBSERVABLE.key,
    "number": OBSERVABLE.number,
    "issuer": OBSERVABLE.issuer,
    "subject": OBSERVABLE.subject,
    "serial_number": OBSERVABLE.serialNumber,
    "version": OBSERVABLE.version,
}

OBJECT_REF_MAP = {
    # Common STIX refs
    "created_by_ref": CTI.createdBy,
    "object_marking_refs": CTI.objectMarking,
    "object_refs": CTI.referencesObject,
    "observed_data_refs": CTI.observedDataRef,
    "where_sighted_refs": CTI.whereSighted,
    "sighting_of_ref": CTI.sightingOf,

    # SCO refs
    "parent_ref": OBSERVABLE.parent,
    "src_ref": OBSERVABLE.source,
    "dst_ref": OBSERVABLE.destination,
    "src_payload_ref": OBSERVABLE.sourcePayload,
    "dst_payload_ref": OBSERVABLE.destinationPayload,
    "binary_ref": OBSERVABLE.binary,
    "image_ref": OBSERVABLE.image,
    "belongs_to_ref": OBSERVABLE.belongsTo,
    "creator_user_ref": OBSERVABLE.creator,
    "from_ref": OBSERVABLE.from_,
    "sender_ref": OBSERVABLE.sender,
    "body_multipart_ref": OBSERVABLE.bodyMultipart,
    "parent_directory_ref": OBSERVABLE.parentDirectory,
    "content_ref": OBSERVABLE.content,
}

# Relationship-specific mapping
REL_SOURCE = CORE.source
REL_TARGET = CORE.target
REL_KIND = CORE.kindOfRelationship

# Bundle-specific mapping
HAS_MEMBER = CTI.hasMember

# Structured helper classes
EXTERNAL_REF_CLASS = CTI.ExternalReference
KILL_CHAIN_PHASE_CLASS = CTI.KillChainPhase
MARKING_DEFINITION_DETAILS_CLASS = CTI.MarkingDefinitionDetails

# =========================
# Utility helpers
# =========================
STIX_DATETIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$"
)

SAFE_FRAGMENT_RE = re.compile(r"[^A-Za-z0-9._-]")


def build_graph() -> Graph:
    g = Graph()
    g.bind("ex", EX)
    g.bind("cti", CTI)
    g.bind("core", CORE)
    g.bind("identity", IDENTITY)
    g.bind("action", ACTION)
    g.bind("tool", TOOL)
    g.bind("pattern", PATTERN)
    g.bind("observable", OBSERVABLE)
    return g


def iri_for(stix_id: str) -> URIRef:
    return EX[stix_id]


def safe_fragment(value: str) -> str:
    return SAFE_FRAGMENT_RE.sub("_", value)


def local_name(uri: URIRef) -> str:
    uri_str = str(uri)
    if "#" in uri_str:
        return uri_str.rsplit("#", 1)[-1]
    return uri_str.rstrip("/").rsplit("/", 1)[-1]


def add_literal(g: Graph, subject: URIRef, predicate: URIRef, value: Any) -> None:
    if value is None:
        return

    if isinstance(value, bool):
        g.add((subject, predicate, Literal(value, datatype=XSD.boolean)))
        return

    if isinstance(value, int) and not isinstance(value, bool):
        g.add((subject, predicate, Literal(value, datatype=XSD.integer)))
        return

    if isinstance(value, float):
        g.add((subject, predicate, Literal(value, datatype=XSD.decimal)))
        return

    if isinstance(value, str):
        if STIX_DATETIME_RE.match(value):
            g.add((subject, predicate, Literal(value, datatype=XSD.dateTime)))
        else:
            g.add((subject, predicate, Literal(value)))
        return

    g.add((subject, predicate, Literal(str(value))))


def add_ref(g: Graph, subject: URIRef, predicate: URIRef, ref_id: str) -> None:
    if ref_id:
        g.add((subject, predicate, iri_for(ref_id)))


def predicate_for_raw_key(key: str) -> URIRef:
    return CTI[f"raw_{safe_fragment(key)}"]


def is_primitive(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool))


# =========================
# Structured mapping helpers
# =========================
def map_external_references(g: Graph, subject: URIRef, obj: Dict[str, Any]) -> None:
    ext_refs = obj.get("external_references")
    if not isinstance(ext_refs, list):
        return

    subject_local = local_name(subject)

    for i, ext_ref in enumerate(ext_refs):
        if not isinstance(ext_ref, dict):
            continue

        ref_key = (
            ext_ref.get("external_id")
            or ext_ref.get("source_name")
            or ext_ref.get("url")
            or f"ref-{i}"
        )

        ref_uri = EX[
            f"{subject_local}-external-reference-{safe_fragment(str(ref_key))}-{i}"
        ]

        g.add((ref_uri, RDF.type, EXTERNAL_REF_CLASS))
        g.add((subject, CTI.hasExternalReference, ref_uri))

        if "source_name" in ext_ref:
            add_literal(g, ref_uri, CTI.sourceName, ext_ref["source_name"])
        if "external_id" in ext_ref:
            add_literal(g, ref_uri, CTI.externalId, ext_ref["external_id"])
        if "url" in ext_ref:
            add_literal(g, ref_uri, CTI.url, ext_ref["url"])
        if "description" in ext_ref:
            add_literal(g, ref_uri, CTI.description, ext_ref["description"])

        hashes = ext_ref.get("hashes")
        if isinstance(hashes, dict):
            for hash_name, hash_value in hashes.items():
                add_literal(
                    g,
                    ref_uri,
                    CTI[f"hash_{safe_fragment(str(hash_name))}"],
                    hash_value,
                )

        for k, v in ext_ref.items():
            if k in {"source_name", "external_id", "url", "description", "hashes"}:
                continue
            if is_primitive(v):
                add_literal(g, ref_uri, predicate_for_raw_key(k), v)
            elif isinstance(v, (list, dict)):
                add_literal(
                    g,
                    ref_uri,
                    predicate_for_raw_key(k),
                    json.dumps(v, ensure_ascii=False),
                )


def map_kill_chain_phases(g: Graph, subject: URIRef, obj: Dict[str, Any]) -> None:
    phases = obj.get("kill_chain_phases")
    if not isinstance(phases, list):
        return

    subject_local = local_name(subject)

    for i, phase in enumerate(phases):
        if not isinstance(phase, dict):
            continue

        kc_name = str(phase.get("kill_chain_name", f"kill-chain-{i}"))
        phase_name = str(phase.get("phase_name", f"phase-{i}"))

        phase_uri = EX[
            f"{subject_local}-kill-chain-phase-"
            f"{safe_fragment(kc_name)}-{safe_fragment(phase_name)}-{i}"
        ]

        g.add((phase_uri, RDF.type, KILL_CHAIN_PHASE_CLASS))
        g.add((subject, CTI.killChainPhase, phase_uri))

        add_literal(g, phase_uri, CTI.killChainName, kc_name)
        add_literal(g, phase_uri, CTI.phaseName, phase_name)

        for k, v in phase.items():
            if k in {"kill_chain_name", "phase_name"}:
                continue
            if is_primitive(v):
                add_literal(g, phase_uri, predicate_for_raw_key(k), v)
            elif isinstance(v, (list, dict)):
                add_literal(
                    g,
                    phase_uri,
                    predicate_for_raw_key(k),
                    json.dumps(v, ensure_ascii=False),
                )


def map_marking_definition_extras(g: Graph, subject: URIRef, obj: Dict[str, Any]) -> None:
    definition = obj.get("definition")
    if not isinstance(definition, dict):
        return

    subject_local = local_name(subject)
    def_uri = EX[f"{subject_local}-definition"]

    g.add((def_uri, RDF.type, MARKING_DEFINITION_DETAILS_CLASS))
    g.add((subject, CTI.definition, def_uri))

    for k, v in definition.items():
        pred = CTI[safe_fragment(k)]

        if is_primitive(v):
            add_literal(g, def_uri, pred, v)
        elif isinstance(v, list):
            for item in v:
                if is_primitive(item):
                    add_literal(g, def_uri, pred, item)
                else:
                    add_literal(g, def_uri, pred, json.dumps(item, ensure_ascii=False))
        elif isinstance(v, dict):
            add_literal(g, def_uri, pred, json.dumps(v, ensure_ascii=False))


def map_granular_markings(g: Graph, subject: URIRef, obj: Dict[str, Any]) -> None:
    granular_markings = obj.get("granular_markings")
    if not isinstance(granular_markings, list):
        return

    for gm in granular_markings:
        add_literal(g, subject, CTI.granularMarking, json.dumps(gm, ensure_ascii=False))


def map_hashes(g: Graph, subject: URIRef, obj: Dict[str, Any]) -> None:
    hashes = obj.get("hashes")
    if not isinstance(hashes, dict):
        return

    for hash_name, hash_value in hashes.items():
        add_literal(
            g,
            subject,
            CTI[f"hash_{safe_fragment(str(hash_name))}"],
            hash_value,
        )


def map_extensions_as_raw(g: Graph, subject: URIRef, obj: Dict[str, Any]) -> None:
    extensions = obj.get("extensions")
    if isinstance(extensions, dict):
        add_literal(g, subject, CTI.raw_extensions, json.dumps(extensions, ensure_ascii=False))


def map_nested_observed_objects(g: Graph, subject: URIRef, obj: Dict[str, Any]) -> None:
    """
    Handles old-style observed-data.objects containers conservatively:
    stores each embedded object as a separate EX node and links it from subject.
    """
    embedded_objects = obj.get("objects")
    if not isinstance(embedded_objects, dict):
        return

    subject_local = local_name(subject)

    for embedded_key, embedded_obj in embedded_objects.items():
        if not isinstance(embedded_obj, dict):
            continue

        embedded_uri = EX[f"{subject_local}-embedded-object-{safe_fragment(str(embedded_key))}"]
        embedded_type = embedded_obj.get("type", "embedded-observable")

        rdf_class = TYPE_MAP.get(embedded_type, CTI.UnknownStixObject)
        g.add((embedded_uri, RDF.type, rdf_class))
        g.add((subject, CTI.embeddedObject, embedded_uri))

        add_literal(g, embedded_uri, CTI.embeddedObjectKey, embedded_key)

        for k, v in embedded_obj.items():
            if is_primitive(v):
                pred = SINGLE_LITERAL_MAP.get(k) or COMMON_LITERAL_MAP.get(k) or predicate_for_raw_key(k)
                add_literal(g, embedded_uri, pred, v)
            elif isinstance(v, list):
                pred = LIST_LITERAL_MAP.get(k) or predicate_for_raw_key(k)
                for item in v:
                    if is_primitive(item):
                        add_literal(g, embedded_uri, pred, item)
                    else:
                        add_literal(g, embedded_uri, pred, json.dumps(item, ensure_ascii=False))
            elif isinstance(v, dict):
                add_literal(g, embedded_uri, predicate_for_raw_key(k), json.dumps(v, ensure_ascii=False))


# =========================
# Main object mapping
# =========================
def map_common_properties(g: Graph, subject: URIRef, obj: Dict[str, Any]) -> None:
    for stix_key, rdf_pred in COMMON_LITERAL_MAP.items():
        if stix_key in obj:
            add_literal(g, subject, rdf_pred, obj[stix_key])

    for stix_key, rdf_pred in LIST_LITERAL_MAP.items():
        values = obj.get(stix_key)
        if isinstance(values, list):
            for v in values:
                if isinstance(v, str) and stix_key.endswith("_refs"):
                    add_ref(g, subject, rdf_pred, v)
                elif is_primitive(v):
                    add_literal(g, subject, rdf_pred, v)
                else:
                    add_literal(g, subject, rdf_pred, json.dumps(v, ensure_ascii=False))

    for stix_key, rdf_pred in SINGLE_LITERAL_MAP.items():
        if stix_key in obj and not isinstance(obj[stix_key], dict):
            add_literal(g, subject, rdf_pred, obj[stix_key])

    for stix_key, rdf_pred in OBJECT_REF_MAP.items():
        if stix_key not in obj:
            continue

        value = obj[stix_key]
        if isinstance(value, list):
            for ref in value:
                if isinstance(ref, str):
                    add_ref(g, subject, rdf_pred, ref)
        elif isinstance(value, str):
            add_ref(g, subject, rdf_pred, value)

    map_external_references(g, subject, obj)
    map_kill_chain_phases(g, subject, obj)
    map_granular_markings(g, subject, obj)
    map_hashes(g, subject, obj)
    map_extensions_as_raw(g, subject, obj)


def map_identity_extras(g: Graph, subject: URIRef, obj: Dict[str, Any]) -> None:
    identity_class = obj.get("identity_class")
    if identity_class == "organization":
        g.add((subject, RDF.type, IDENTITY.Organization))
    elif identity_class == "individual":
        g.add((subject, RDF.type, IDENTITY.Person))
    elif identity_class == "group":
        g.add((subject, RDF.type, IDENTITY.OrganizationalUnit))


def map_relationship(g: Graph, subject: URIRef, obj: Dict[str, Any]) -> None:
    source_ref = obj.get("source_ref")
    target_ref = obj.get("target_ref")
    relationship_type = obj.get("relationship_type")

    if source_ref:
        g.add((subject, REL_SOURCE, iri_for(source_ref)))
        add_literal(g, subject, CTI.sourceRef, source_ref)

    if target_ref:
        g.add((subject, REL_TARGET, iri_for(target_ref)))
        add_literal(g, subject, CTI.targetRef, target_ref)

    if relationship_type:
        add_literal(g, subject, REL_KIND, relationship_type)
        add_literal(g, subject, CTI.relationshipType, relationship_type)


def map_bundle(g: Graph, bundle_obj: Dict[str, Any], member_objects: List[Dict[str, Any]]) -> None:
    bundle_id = bundle_obj.get("id")
    if not bundle_id:
        return

    bundle_subject = iri_for(bundle_id)
    g.add((bundle_subject, RDF.type, CORE.Bundle))

    add_literal(g, bundle_subject, CTI.stixId, bundle_id)
    add_literal(g, bundle_subject, CTI.stixType, "bundle")

    spec_version = bundle_obj.get("spec_version")
    if spec_version is not None:
        add_literal(g, bundle_subject, CTI.specVersion, spec_version)

    for member in member_objects:
        member_id = member.get("id")
        if member_id:
            g.add((bundle_subject, HAS_MEMBER, iri_for(member_id)))


def known_keys() -> set:
    return (
        set(COMMON_LITERAL_MAP.keys())
        | set(LIST_LITERAL_MAP.keys())
        | set(SINGLE_LITERAL_MAP.keys())
        | set(OBJECT_REF_MAP.keys())
        | {
            "source_ref",
            "target_ref",
            "relationship_type",
            "external_references",
            "kill_chain_phases",
            "granular_markings",
            "definition",
            "objects",
            "hashes",
            "extensions",
        }
    )


def map_unknown_properties(g: Graph, subject: URIRef, obj: Dict[str, Any]) -> None:
    for key, value in obj.items():
        if key in known_keys():
            continue

        pred = predicate_for_raw_key(key)

        if is_primitive(value):
            add_literal(g, subject, pred, value)
        elif isinstance(value, list):
            for item in value:
                if is_primitive(item):
                    add_literal(g, subject, pred, item)
                else:
                    add_literal(g, subject, pred, json.dumps(item, ensure_ascii=False))
        elif isinstance(value, dict):
            add_literal(g, subject, pred, json.dumps(value, ensure_ascii=False))


def map_object(g: Graph, obj: Dict[str, Any]) -> None:
    stix_type = obj.get("type")
    stix_id = obj.get("id")

    if not stix_type or not stix_id:
        return

    subject = iri_for(stix_id)
    rdf_class = TYPE_MAP.get(stix_type, CTI.UnknownStixObject)

    g.add((subject, RDF.type, rdf_class))

    map_common_properties(g, subject, obj)

    if stix_type == "identity":
        map_identity_extras(g, subject, obj)

    if stix_type == "relationship":
        map_relationship(g, subject, obj)

    if stix_type == "marking-definition":
        map_marking_definition_extras(g, subject, obj)

    if stix_type == "observed-data":
        map_nested_observed_objects(g, subject, obj)

    map_unknown_properties(g, subject, obj)


# =========================
# File I/O
# =========================
def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def convert_file(json_path: Path, output_ttl_path: Path) -> Graph:
    data = load_json(json_path)
    g = build_graph()

    if data.get("type") == "bundle":
        objects = data.get("objects", [])
        map_bundle(g, data, objects)
        for obj in objects:
            if isinstance(obj, dict):
                map_object(g, obj)
    else:
        map_object(g, data)

    output_ttl_path.parent.mkdir(parents=True, exist_ok=True)
    g.serialize(destination=str(output_ttl_path), format="turtle")
    return g


def main() -> None:
    print("STARTING SCRIPT...")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    merged_graph = build_graph()

    json_files = sorted(INPUT_DIR.rglob("code.json"))

    if not json_files:
        print(f"No code.json files found under: {INPUT_DIR}")
        return

    for json_file in json_files:
        example_name = json_file.parent.name
        safe_name = example_name.replace(" ", "_").replace("/", "_")
        out_file = OUTPUT_DIR / f"{safe_name}.ttl"

        print(f"[INFO] Converting: {json_file}")
        g = convert_file(json_file, out_file)

        for triple in g:
            merged_graph.add(triple)

        print(f"[OK] Wrote: {out_file}")

    merged_out = OUTPUT_DIR / "all_examples.ttl"
    merged_graph.serialize(destination=str(merged_out), format="turtle")
    print(f"[OK] Wrote merged file: {merged_out}")


if __name__ == "__main__":
    main()