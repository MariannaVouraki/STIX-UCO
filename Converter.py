import json
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
INPUT_DIR = BASE_DIR / "STIX_EXAMPLES"
OUTPUT_DIR = BASE_DIR / "02_Output" / "ttl"

# =========================
# Type mapping
# =========================
TYPE_MAP = {
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
}

# =========================
# Common property mapping
# =========================
COMMON_LITERAL_MAP = {
    "name": CORE.name,
    "description": CORE.description,
    "created": CTI.stixCreated,
    "modified": CTI.stixModified,
    "spec_version": CTI.specVersion,
    "revoked": CTI.revoked,
}

LIST_LITERAL_MAP = {
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
}

SINGLE_LITERAL_MAP = {
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
    "definition": CTI.definition,
    "count": CTI.sightingCount,
    "number_observed": CTI.numberObserved,
    "first_seen": CTI.firstSeen,
    "last_seen": CTI.lastSeen,
    "first_observed": CTI.firstObserved,
    "last_observed": CTI.lastObserved,
    "valid_from": CTI.validFrom,
    "valid_until": CTI.validUntil,
}

OBJECT_REF_MAP = {
    "created_by_ref": CTI.createdBy,
    "object_marking_refs": CTI.objectMarking,
    "object_refs": CTI.referencesObject,
    "observed_data_refs": CTI.observedDataRef,
    "where_sighted_refs": CTI.whereSighted,
    "sighting_of_ref": CTI.sightingOf,
}

# Relationship-specific mapping
REL_SOURCE = CORE.source
REL_TARGET = CORE.target
REL_KIND = CORE.kindOfRelationship

# Bundle-specific mapping
HAS_MEMBER = CTI.hasMember


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


def add_literal(g: Graph, subject: URIRef, predicate: URIRef, value: Any) -> None:
    if value is None:
        return

    if isinstance(value, bool):
        g.add((subject, predicate, Literal(value, datatype=XSD.boolean)))
    elif isinstance(value, int):
        g.add((subject, predicate, Literal(value, datatype=XSD.integer)))
    else:
        # Keep timestamps and strings as literals for v1
        g.add((subject, predicate, Literal(value)))


def add_ref(g: Graph, subject: URIRef, predicate: URIRef, ref_id: str) -> None:
    if ref_id:
        g.add((subject, predicate, iri_for(ref_id)))


def map_common_properties(g: Graph, subject: URIRef, obj: Dict[str, Any]) -> None:
    for stix_key, rdf_pred in COMMON_LITERAL_MAP.items():
        if stix_key in obj:
            add_literal(g, subject, rdf_pred, obj[stix_key])

    for stix_key, rdf_pred in LIST_LITERAL_MAP.items():
        values = obj.get(stix_key)
        if isinstance(values, list):
            for v in values:
                add_literal(g, subject, rdf_pred, v)

    for stix_key, rdf_pred in SINGLE_LITERAL_MAP.items():
        if stix_key in obj:
            add_literal(g, subject, rdf_pred, obj[stix_key])

    # Generic refs
    for stix_key, rdf_pred in OBJECT_REF_MAP.items():
        if stix_key not in obj:
            continue

        value = obj[stix_key]
        if isinstance(value, list):
            for ref in value:
                add_ref(g, subject, rdf_pred, ref)
        elif isinstance(value, str):
            add_ref(g, subject, rdf_pred, value)

    # Preserve external references and kill chain phases conservatively as literals
    if "external_references" in obj:
        for ext_ref in obj["external_references"]:
            add_literal(g, subject, CTI.externalReference, json.dumps(ext_ref, ensure_ascii=False))

    if "kill_chain_phases" in obj:
        for phase in obj["kill_chain_phases"]:
            add_literal(g, subject, CTI.killChainPhase, json.dumps(phase, ensure_ascii=False))

    if "granular_markings" in obj:
        for gm in obj["granular_markings"]:
            add_literal(g, subject, CTI.granularMarking, json.dumps(gm, ensure_ascii=False))


def map_identity_extras(g: Graph, subject: URIRef, obj: Dict[str, Any]) -> None:
    identity_class = obj.get("identity_class")
    if identity_class == "organization":
        g.add((subject, RDF.type, IDENTITY.Organization))


def map_relationship(g: Graph, subject: URIRef, obj: Dict[str, Any]) -> None:
    source_ref = obj.get("source_ref")
    target_ref = obj.get("target_ref")
    relationship_type = obj.get("relationship_type")

    if source_ref:
        g.add((subject, REL_SOURCE, iri_for(source_ref)))
    if target_ref:
        g.add((subject, REL_TARGET, iri_for(target_ref)))
    if relationship_type:
        add_literal(g, subject, REL_KIND, relationship_type)


def map_bundle(g: Graph, bundle_obj: Dict[str, Any], member_objects: List[Dict[str, Any]]) -> None:
    bundle_id = bundle_obj.get("id")
    if not bundle_id:
        return

    bundle_subject = iri_for(bundle_id)
    g.add((bundle_subject, RDF.type, CORE.Bundle))

    for member in member_objects:
        member_id = member.get("id")
        if member_id:
            g.add((bundle_subject, HAS_MEMBER, iri_for(member_id)))


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
            map_object(g, obj)
    else:
        # fallback if root is a plain STIX object
        map_object(g, data)

    output_ttl_path.parent.mkdir(parents=True, exist_ok=True)
    g.serialize(destination=str(output_ttl_path), format="turtle")
    return g


def main() -> None:
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