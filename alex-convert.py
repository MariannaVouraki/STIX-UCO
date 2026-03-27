import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from rdflib import Graph, Namespace, URIRef, Literal
from rdflib.namespace import RDF, RDFS, OWL, XSD


UCO_NAMESPACE = "https://unifiedcyberontology.org/ontology#"
UCO = Namespace(UCO_NAMESPACE)

# Mirrors the Java static map
resources: Dict[str, URIRef] = {}

# Mirrors the Java static "Stixthing" Resource (bundle id resource)
STIXTHING: Optional[URIRef] = None


DATE_FORMATS = ["%Y-%m-%d", "%d-%m-%Y", "%m/%d/%Y", "%Y/%m/%d"]


def get_as_string(obj: Dict[str, Any], key: str) -> Optional[str]:
    v = obj.get(key)
    if v is None:
        return None
    if isinstance(v, str):
        return v
    # The Java code assumes primitive->string for many properties
    return str(v)


def ucoclass(stix_type: str) -> str:
    """
    Port of Java ucoclass():
    - Capitalize first letter
    - If contains '-', remove it and uppercase the char after '-'
      (only handles first '-' in the Java loop effectively)
    """
    if not stix_type:
        return stix_type
    chars = list(stix_type)
    chars[0] = chars[0].upper()

    if "-" in stix_type:
        for i, ch in enumerate(chars):
            if ch == "-":
                # shift left while uppercasing the next char at position i
                for j in range(i, len(chars) - 1):
                    if j == i:
                        chars[i] = chars[i + 1].upper()
                    else:
                        chars[j] = chars[j + 1]
                chars = chars[:-1]
                return "".join(chars)
    return "".join(chars)


def map_stix_to_uco_property(stix_property: str) -> str:
    mapping = {
        "created": "created",
        "modified": "modified",
        "name": "name",
        "description": "description",
        "labels": "labels",
        "pattern": "pattern",
        "valid_from": "validFrom",
        "id": "id",
        "first_seen": "firstSeen",
        "last_seen": "lastSeen",
        "spec_version": "specVersion",
        "sectors": "sector",
        "aliases": "alias",
        "objective": "goals",
        "identity_class": "identityClass",
        "is_family": "isFamily",
        "number_observed": "value",
        "first_observed": "firstObserved",
        "last_observed": "lastObserved",
        "opinion": "opinion",
        "published": "published",
        "sophistication": "skillLevel",
        "pattern_type": "patternType",
        "revoked": "revoked",
        "country": "country",
        "relationship_type": "relationshipType",
        "sighting": "Sighting",
        "definition_type": "definitionType",
        "object_marking_refs": "objectMarking",
        "threat_actor_types": "label",
        "primary_motivation": "primaryMotivation",
        "malware_types": "malwareTypes",
        "indicator_types": "indicatorTypes",
        "kill_chain_phases": "killChainPhase",
        "sighting_of_ref": "sightingOf",
        "created_by_ref": "createdBy",
        "observed_data_refs": "observed",
        "resource_level": "resourseLevel",
        "contact_information": "contactInformation",
    }
    return mapping.get(stix_property, stix_property)


def map_stix_to_uco_reverse_property(stix_property: str) -> str:
    mapping = {
        "uses": "usedBy",
        "where_sighted": "sightedBy",
        "source": "sourceOf",
        "target": "targetOf",
        "attributedTo": "attributionOf",
        "createdBy": "creatorOf",
        "delivers": "deliveredFrom",
        "exploits": "exploitedBy",
        "indicates": "indicatedBy",
        "mitigates": "mitigatedBy",
    }
    return mapping.get(stix_property, "no_change")


def map_stix_to_uco_relationship(stix_relationship: str) -> str:
    mapping = {
        "uses": "uses",
        "targets": "targets",
        "indicates": "indicates",
        "mitigates": "mitigates",
        "attributed-to": "attributedTo",
        "exploits": "exploits",
        "variant-of": "variant",
        "authored-by": "authoredBy",
        "impersonates": "impersonates",
        "duplicate-of": "duplicateOf",
        "delivered-from": "deliveredFrom",
        "related-to": "relatedTo",
        "based-on": "basedOn",
        "located-at": "locatedAt",
        "delivers": "delivers",
    }
    return mapping.get(stix_relationship, stix_relationship)


def is_integer(s: str) -> bool:
    try:
        int(s)
        return True
    except Exception:
        return False


def is_float(s: str) -> bool:
    try:
        float(s)
        return True
    except Exception:
        return False


def is_boolean(s: str) -> bool:
    return s.lower() in ("true", "false")


def is_date(s: str) -> bool:
    for fmt in DATE_FORMATS:
        try:
            datetime.strptime(s, fmt)
            return True
        except Exception:
            continue
    return False


def detect_literal_type(s: str) -> str:
    # same order as Java
    if is_integer(s):
        return "Integer"
    if is_date(s):
        return "Date"
    if is_float(s):
        return "Float"
    if is_boolean(s):
        return "Boolean"
    return "String"


def add_datatype_property(g: Graph, prop: URIRef):
    g.add((prop, RDF.type, OWL.DatatypeProperty))


def add_object_property(g: Graph, prop: URIRef):
    g.add((prop, RDF.type, OWL.ObjectProperty))


def handle_external_references(g: Graph, external_refs: list, resource: URIRef):
    for ref in external_refs:
        if not isinstance(ref, dict):
            continue

        external_id = get_as_string(ref, "external_id")
        source_name = get_as_string(ref, "source_name")

        if external_id is None and source_name is not None:
            external_id = source_name.replace(" ", "-")

        if external_id is None:
            continue

        external_ref_class = UCO["ExternalReference"]
        g.add((external_ref_class, RDF.type, RDFS.Class))

        external_ref_res = UCO[f"external-reference--{external_id}"]
        g.add((external_ref_res, RDF.type, external_ref_class))

        if source_name is not None:
            g.add((external_ref_res, UCO["sourceName"], Literal(source_name, datatype=XSD.string)))
            add_datatype_property(g, UCO["sourceName"])

        url = get_as_string(ref, "url")
        if url is not None:
            g.add((external_ref_res, UCO["url"], Literal(url, datatype=XSD.string)))
            add_datatype_property(g, UCO["url"])

        desc = get_as_string(ref, "description")
        if desc is not None:
            g.add((external_ref_res, UCO["description"], Literal(desc, datatype=XSD.string)))
            add_datatype_property(g, UCO["description"])

        g.add((resource, UCO["hasExternalReference"], external_ref_res))
        add_object_property(g, UCO["hasExternalReference"])


def handle_references(g: Graph, stix_obj: Dict[str, Any], resource: URIRef):
    # Relationship triple expansion (only if both endpoints already seen)
    if all(k in stix_obj for k in ("relationship_type", "source_ref", "target_ref")):
        rel_type = map_stix_to_uco_relationship(get_as_string(stix_obj, "relationship_type") or "")
        src = get_as_string(stix_obj, "source_ref")
        tgt = get_as_string(stix_obj, "target_ref")

        if src and tgt:
            src_res = resources.get(src)
            tgt_res = resources.get(tgt)
            if src_res is not None and tgt_res is not None:
                g.add((src_res, UCO[rel_type], tgt_res))
                add_object_property(g, UCO[rel_type])

                rev = map_stix_to_uco_reverse_property(rel_type)
                if rev == "no_change":
                    g.add((tgt_res, UCO[f"linkedFrom{rel_type}"], src_res))
                    add_object_property(g, UCO[f"linkedFrom{rel_type}"])
                else:
                    g.add((tgt_res, UCO[rev], src_res))
                    add_object_property(g, UCO[rev])

    # Generic *_ref and *_refs processing (only links if referenced resource already exists in dict)
    for key, val in stix_obj.items():
        if key.endswith("_ref") and isinstance(val, str):
            referenced_id = val
            referenced_res = resources.get(referenced_id)
            if referenced_res is None:
                continue

            property_name = map_stix_to_uco_property(key).replace("_ref", "")
            g.add((resource, UCO[property_name], referenced_res))
            add_object_property(g, UCO[property_name])

            rev = map_stix_to_uco_reverse_property(property_name)
            if rev == "no_change":
                g.add((referenced_res, UCO[f"linkedFrom{property_name}"], resource))
                add_object_property(g, UCO[f"linkedFrom{property_name}"])
            else:
                g.add((referenced_res, UCO[rev], resource))
                add_object_property(g, UCO[rev])

        elif key.endswith("_refs") and isinstance(val, list):
            for ref_id in val:
                if not isinstance(ref_id, str):
                    continue
                referenced_res = resources.get(ref_id)
                if referenced_res is None:
                    continue

                property_name = key.replace("_refs", "")  # note: Java does NOT map here
                g.add((resource, UCO[property_name], referenced_res))
                add_object_property(g, UCO[property_name])

                rev = map_stix_to_uco_reverse_property(property_name)
                if rev == "no_change":
                    g.add((referenced_res, UCO[f"linkedFrom{property_name}"], resource))
                    add_object_property(g, UCO[f"linkedFrom{property_name}"])
                else:
                    g.add((referenced_res, UCO[rev], resource))
                    add_object_property(g, UCO[rev])


def handle_property(g: Graph, resource: URIRef, key: str, value: Any):
    uco_prop = map_stix_to_uco_property(key)
    prop = UCO[uco_prop]

    # kill_chain_phases special
    if key == "kill_chain_phases" and isinstance(value, list):
        kill_chain_phase_class = UCO["KillChainPhase"]
        g.add((kill_chain_phase_class, RDF.type, RDFS.Class))

        for elem in value:
            if not isinstance(elem, dict):
                continue
            kill_chain_name = get_as_string(elem, "kill_chain_name") or ""
            phase_name = get_as_string(elem, "phase_name") or ""

            kill_chain_uri = UCO[f"kill_chain--{kill_chain_name}"]
            g.add((kill_chain_uri, RDF.type, kill_chain_phase_class))

            g.add((kill_chain_uri, UCO["killChainName"], Literal(kill_chain_name, datatype=XSD.string)))
            g.add((kill_chain_uri, UCO["phaseName"], Literal(phase_name, datatype=XSD.string)))
            add_datatype_property(g, UCO["killChainName"])
            add_datatype_property(g, UCO["phaseName"])

            g.add((resource, prop, kill_chain_uri))
            add_object_property(g, prop)
        return

    # *_refs arrays as object properties (creates URI even if not in resources)
    if key.endswith("_refs") and isinstance(value, list):
        for ref_id in value:
            if isinstance(ref_id, str):
                g.add((resource, prop, UCO[ref_id]))
                add_object_property(g, prop)
        return

    # primitive literal
    if isinstance(value, (str, int, float, bool)):
        s = str(value)
        t = detect_literal_type(s)
        if t == "Integer":
            lit = Literal(s, datatype=XSD.integer)
        elif t == "Date":
            lit = Literal(s, datatype=XSD.date)
        elif t == "Float":
            lit = Literal(s, datatype=XSD.float)
        elif t == "Boolean":
            lit = Literal(s.lower(), datatype=XSD.boolean)
        else:
            lit = Literal(s, datatype=XSD.string)

        add_datatype_property(g, prop)
        g.add((resource, prop, lit))
        return

    # arrays
    if isinstance(value, list):
        for elem in value:
            if isinstance(elem, (str, int, float, bool)):
                # Java splits each primitive element on "-"
                for part in str(elem).split("-"):
                    lit = Literal(part.strip(), datatype=XSD.string)
                    add_datatype_property(g, prop)
                    g.add((resource, prop, lit))
            elif isinstance(elem, dict):
                handle_stix_object(g, elem)
        return

    # nested object
    if isinstance(value, dict):
        if "id" in value and isinstance(value["id"], str):
            ref_id = value["id"]
            g.add((resource, prop, UCO[ref_id]))
            add_object_property(g, prop)
            handle_stix_object(g, value)
        return


def handle_stix_object(g: Graph, stix_obj: Dict[str, Any]):
    global STIXTHING

    obj_id = get_as_string(stix_obj, "id")
    obj_type = get_as_string(stix_obj, "type")
    if obj_id is None or obj_type is None:
        return

    res = UCO[obj_id]

    # type/class assignment logic (ported as-is, including typos)
    if obj_type == "relationship":
        relationship_class = UCO["Relationship"]
        g.add((relationship_class, RDF.type, RDFS.Class))

        rel_type = map_stix_to_uco_relationship(get_as_string(stix_obj, "relationship_type") or "")
        g.add((UCO[rel_type], RDF.type, OWL.ObjectProperty))

        if STIXTHING is not None:
            g.add((STIXTHING, RDFS.subClassOf, relationship_class))
        g.add((res, RDF.type, relationship_class))

    elif obj_type == "sighting":
        sighing_class = UCO["Sighing"]  # typo preserved from Java
        g.add((sighing_class, RDF.type, RDFS.Class))
        if STIXTHING is not None:
            g.add((STIXTHING, RDFS.subClassOf, sighing_class))
        g.add((res, RDF.type, sighing_class))

    elif obj_type == "course-of-action":
        coa_class = UCO["CourseOfAction"]
        g.add((coa_class, RDF.type, RDFS.Class))
        if STIXTHING is not None:
            g.add((STIXTHING, RDFS.subClassOf, coa_class))
        g.add((res, RDF.type, coa_class))

    else:
        uco_class = UCO[ucoclass(obj_type)]
        g.add((uco_class, RDF.type, RDFS.Class))
        if STIXTHING is not None:
            g.add((STIXTHING, RDFS.subClassOf, uco_class))
        g.add((res, RDF.type, uco_class))

    resources[obj_id] = res

    # properties
    for k, v in stix_obj.items():
        if k in ("id", "type"):
            continue
        handle_property(g, res, k, v)

    # external references
    if isinstance(stix_obj.get("external_references"), list):
        handle_external_references(g, stix_obj["external_references"], res)

    # cross-object references
    handle_references(g, stix_obj, res)


def convert_file(input_path: Path) -> Graph:
    global STIXTHING
    resources.clear()

    with input_path.open("r", encoding="utf-8") as f:
        bundle = json.load(f)

    g = Graph()
    g.bind("uco", UCO)

    bundle_id = get_as_string(bundle, "id") or "bundle--unknown"
    STIXTHING = UCO[bundle_id]
    g.add((STIXTHING, RDF.type, RDFS.Class))

    objects = bundle.get("objects")
    if isinstance(objects, list):
        for obj in objects:
            if isinstance(obj, dict):
                handle_stix_object(g, obj)

    return g


def main():
    print("STARTING SCRIPT...")
    ap = argparse.ArgumentParser(description="Convert a STIX bundle JSON to UCO-like RDF Turtle (ported from Java).")
    ap.add_argument("input", help="Path to STIX bundle JSON")
    ap.add_argument("-o", "--output", help="Output TTL file path. If omitted, prints to stdout.")
    args = ap.parse_args()

    g = convert_file(Path(args.input))

    ttl = g.serialize(format="turtle")
    if args.output:
        Path(args.output).write_text(ttl, encoding="utf-8")
        print(f"Wrote: {args.output}")
    else:
        print(ttl)


if __name__ == "__main__":
    main()