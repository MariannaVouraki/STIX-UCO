# STIX 2.1 → UCO Mapping Specification (v1)

## Purpose

This document defines the initial mapping strategy for converting STIX 2.1 JSON examples into RDF/Turtle using UCO as the semantic backbone.

The goal is **not** to force a perfect 1:1 official crosswalk for every STIX concept.  
The goal is to produce a **stable, conservative, and extensible** transformation pipeline that:

1. preserves the original STIX semantics as safely as possible,
2. reuses native UCO classes/properties where there is a clean fit,
3. uses a small local extension namespace (`cti:`) where UCO does not offer a verified direct equivalent,
4. produces RDF triples suitable for loading into Virtuoso.

---

## Modeling principles

### 1. UCO-first approach
Use native UCO classes and properties whenever there is a clear semantic match.

### 2. Conservative mapping
If a native UCO property/class is unclear or not verified, do **not** guess.  
Use either:
- a reified `core:Relationship`, or
- a local extension property/class in the `cti:` namespace.

### 3. Preserve STIX structure safely
STIX objects should remain individually addressable resources using their STIX IDs as IRIs.

Example:
- `indicator--...`
- `malware--...`
- `relationship--...`

### 4. Bundle is a container
A STIX `bundle` is treated primarily as a container, not as a domain-level cyber entity.
It may still be represented as `core:Bundle`, with local membership links via `cti:hasMember`.

### 5. Relationship objects stay reified
STIX `relationship` objects should be represented as instances of `core:Relationship` with:
- `core:source`
- `core:target`
- `core:kindOfRelationship` or `core:name`

This avoids inventing UCO predicates such as `uses`, `targets`, `delivers`, etc., unless explicitly verified later.

### 6. Open vocabularies remain annotations
STIX fields such as:
- `labels`
- `goals`
- `roles`
- `threat_actor_types`
- `primary_motivation`
- `secondary_motivations`
- `sophistication`
- `resource_level`

should initially be preserved as literals, preferably in local extension properties or temporary annotation properties.

---

## Namespaces

```ttl
@prefix ex: <http://example.org/stix-uco/> .
@prefix core: <https://ontology.unifiedcyberontology.org/uco/core/> .
@prefix identity: <https://ontology.unifiedcyberontology.org/uco/identity/> .
@prefix action: <https://ontology.unifiedcyberontology.org/uco/action/> .
@prefix tool: <https://ontology.unifiedcyberontology.org/uco/tool/> .
@prefix pattern: <https://ontology.unifiedcyberontology.org/uco/pattern/> .
@prefix observable: <https://ontology.unifiedcyberontology.org/uco/observable/> .
@prefix cti: <http://example.org/cti-ext/> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
```

---

## IRI policy

Each STIX object is converted to an RDF resource using its original STIX `id`.

Example:

- STIX ID: `malware--1234abcd-...`
- RDF IRI: `ex:malware--1234abcd-...`

Rule:
- `iri_for(stix_id) = ex:{stix_id}`

This ensures stable traceability between source JSON and RDF output.

---

## Core object type mapping

| STIX object type | Recommended UCO class | Strategy | Notes |
|---|---|---|---|
| `bundle` | `core:Bundle` | direct + extension | Use `cti:hasMember` for contained objects |
| `relationship` | `core:Relationship` | reified | Use `core:source`, `core:target`, and relation label |
| `identity` | `identity:Identity` / `identity:Organization` | conditional | If `identity_class = organization`, also type as `identity:Organization` |
| `threat-actor` | `identity:Organization` | pragmatic default | Good first approximation for named groups/actors |
| `attack-pattern` | `action:ActionPattern` | direct | Clean semantic fit |
| `campaign` | `core:Event` | direct | Better than grouping for time-bound operations |
| `intrusion-set` | `identity:Identity` or `core:Grouping` | pragmatic | Start with `identity:Identity`; revisit later if needed |
| `malware` | `tool:MaliciousTool` | direct | Practical UCO-first mapping |
| `tool` | `tool:Tool` / `tool:MaliciousTool` | conditional | Use `MaliciousTool` only if explicitly offensive/malicious |
| `course-of-action` | `action:Action` | direct | Defensive or mitigating action |
| `report` | `core:Compilation` | direct | Assembled intelligence product |
| `indicator` | `pattern:Pattern` | direct + extension | Keep raw STIX pattern string in `cti:stixPattern` |
| `observed-data` | `core:Event` | wrapper model | Observation wrapper; related observables may be separate nodes |
| `sighting` | `core:Relationship` | reified + extension | Keep count/seen dates in `cti:` properties |
| `marking-definition` | `core:MarkingDefinitionAbstraction` | direct | Use marking abstraction layer |
| `vulnerability` | `cti:Vulnerability` | local extension | Safer than inventing a native UCO class |
| `note` | `core:Note` or `cti:Note` | extension-first | Only add native UCO if verified |
| `opinion` | `cti:Opinion` | local extension | Safer initial modeling |

---

## Common property mapping

These properties should be handled for most STIX Domain Objects.

| STIX property | RDF/UCO mapping | Type | Notes |
|---|---|---|---|
| `id` | implicit in subject IRI | structural | Do not duplicate unless needed |
| `type` | `rdf:type` | structural | Derived from mapping table |
| `name` | `core:name` | literal | Plain string |
| `description` | `core:description` | literal | Plain string |
| `created` | `cti:stixCreated` | datetime literal | Keep original STIX timestamp |
| `modified` | `cti:stixModified` | datetime literal | Keep original STIX timestamp |
| `created_by_ref` | `cti:createdBy` | object property | Link to referenced STIX object |
| `object_marking_refs` | `cti:objectMarking` | object property | One triple per reference |
| `labels` | `cti:label` | literal | Preserve as-is |
| `revoked` | `cti:revoked` | boolean literal | Preserve as-is |
| `spec_version` | `cti:specVersion` | literal | Preserve as-is |
| `external_references` | `cti:externalReference` | node or literal | Start simple; refine later |
| `granular_markings` | `cti:granularMarking` | node or literal | Preserve structure conservatively |

---

## Bundle handling

### Rule
When a STIX object has:

```json
{
  "type": "bundle",
  "id": "bundle--...",
  "objects": [ ... ]
}
```

map it as:

- subject typed as `core:Bundle`
- each contained object linked with `cti:hasMember`

### Example

```ttl
ex:bundle--1
    a core:Bundle ;
    cti:hasMember ex:indicator--1 ;
    cti:hasMember ex:malware--1 ;
    cti:hasMember ex:relationship--1 .
```

### Notes
- The bundle should not be treated as the semantic parent of all inner objects.
- It is a packaging/container construct.

---

## Relationship handling

### Rule
Every STIX `relationship` object remains a reified node.

### Required mappings

| STIX field | RDF mapping |
|---|---|
| `source_ref` | `core:source` |
| `target_ref` | `core:target` |
| `relationship_type` | `core:kindOfRelationship` or `core:name` |

### Example

```ttl
ex:relationship--123
    a core:Relationship ;
    core:source ex:campaign--1 ;
    core:target ex:attack-pattern--1 ;
    core:kindOfRelationship "uses" .
```

### Why this is the default
This is the safest generic transformation because it avoids claiming that every STIX `relationship_type` has an exact native UCO predicate.

---

## Object-specific mapping rules

### 1. identity

#### Class rule
- default: `identity:Identity`
- if `identity_class = "organization"`: also add `identity:Organization`

#### Property mapping
| STIX field | RDF mapping |
|---|---|
| `identity_class` | `cti:identityClass` |
| `roles` | `cti:role` |
| `sectors` | `cti:sector` |

---

### 2. threat-actor

#### Class rule
- default: `identity:Organization`

#### Property mapping
| STIX field | RDF mapping |
|---|---|
| `threat_actor_types` | `cti:threatActorType` |
| `goals` | `cti:goal` |
| `roles` | `cti:role` |
| `primary_motivation` | `cti:primaryMotivation` |
| `secondary_motivations` | `cti:secondaryMotivation` |
| `sophistication` | `cti:sophistication` |
| `resource_level` | `cti:resourceLevel` |
| `first_seen` | `cti:firstSeen` |
| `last_seen` | `cti:lastSeen` |

---

### 3. attack-pattern

#### Class rule
- `action:ActionPattern`

#### Property mapping
| STIX field | RDF mapping |
|---|---|
| `aliases` | `cti:alias` |
| `kill_chain_phases` | `cti:killChainPhase` |

---

### 4. campaign

#### Class rule
- `core:Event`

#### Property mapping
| STIX field | RDF mapping |
|---|---|
| `aliases` | `cti:alias` |
| `objective` | `cti:objective` |
| `first_seen` | `cti:firstSeen` |
| `last_seen` | `cti:lastSeen` |

---

### 5. intrusion-set

#### Class rule
- initial default: `identity:Identity`

#### Property mapping
| STIX field | RDF mapping |
|---|---|
| `aliases` | `cti:alias` |
| `goals` | `cti:goal` |
| `resource_level` | `cti:resourceLevel` |
| `primary_motivation` | `cti:primaryMotivation` |
| `secondary_motivations` | `cti:secondaryMotivation` |
| `first_seen` | `cti:firstSeen` |
| `last_seen` | `cti:lastSeen` |

---

### 6. malware

#### Class rule
- `tool:MaliciousTool`

#### Property mapping
| STIX field | RDF mapping |
|---|---|
| `is_family` | `cti:isFamily` |
| `malware_types` | `cti:malwareType` |
| `aliases` | `cti:alias` |
| `kill_chain_phases` | `cti:killChainPhase` |
| `first_seen` | `cti:firstSeen` |
| `last_seen` | `cti:lastSeen` |

---

### 7. tool

#### Class rule
- default: `tool:Tool`
- optional later rule: promote to `tool:MaliciousTool` if clearly offensive

#### Property mapping
| STIX field | RDF mapping |
|---|---|
| `tool_types` | `cti:toolType` |
| `aliases` | `cti:alias` |
| `kill_chain_phases` | `cti:killChainPhase` |

---

### 8. course-of-action

#### Class rule
- `action:Action`

#### Property mapping
| STIX field | RDF mapping |
|---|---|
| `action`-related text | `core:description` or `cti:actionNote` |

---

### 9. report

#### Class rule
- `core:Compilation`

#### Property mapping
| STIX field | RDF mapping |
|---|---|
| `published` | `cti:published` |
| `report_types` | `cti:reportType` |
| `object_refs` | `cti:referencesObject` |

---

### 10. indicator

#### Class rule
- `pattern:Pattern`

#### Property mapping
| STIX field | RDF mapping |
|---|---|
| `pattern` | `cti:stixPattern` |
| `pattern_type` | `cti:patternType` |
| `indicator_types` | `cti:indicatorType` |
| `valid_from` | `cti:validFrom` |
| `valid_until` | `cti:validUntil` |
| `kill_chain_phases` | `cti:killChainPhase` |

### Note
Do not try to decompose the STIX pattern language into full UCO structure in v1.
Keep the raw pattern string intact.

---

### 11. observed-data

#### Class rule
- `core:Event`

#### Property mapping
| STIX field | RDF mapping |
|---|---|
| `first_observed` | `cti:firstObserved` |
| `last_observed` | `cti:lastObserved` |
| `number_observed` | `cti:numberObserved` |
| `object_refs` | `cti:observedObject` |
| embedded SCOs | separate observable resources | optional v2 |

### Note
For v1, treat `observed-data` as an observation wrapper.
Modeling all SCO internals can be a second phase.

---

### 12. sighting

#### Class rule
- `core:Relationship`

#### Property mapping
| STIX field | RDF mapping |
|---|---|
| `sighting_of_ref` | `cti:sightingOf` |
| `where_sighted_refs` | `cti:whereSighted` |
| `observed_data_refs` | `cti:observedDataRef` |
| `count` | `cti:sightingCount` |
| `first_seen` | `cti:firstSeen` |
| `last_seen` | `cti:lastSeen` |

### Note
`Sighting` behaves like an event/relationship hybrid.
For v1, keep it reified and explicit.

---

### 13. marking-definition

#### Class rule
- `core:MarkingDefinitionAbstraction`

#### Property mapping
| STIX field | RDF mapping |
|---|---|
| `definition_type` | `cti:definitionType` |
| `definition` | `cti:definition` |

---

### 14. vulnerability

#### Class rule
- `cti:Vulnerability`

#### Property mapping
| STIX field | RDF mapping |
|---|---|
| `name` | `core:name` |
| `description` | `core:description` |
| `external_references` | `cti:externalReference` |

### Note
Keep this as a local extension class in v1.

---

## Reference handling

### Single reference
Any STIX field ending in `_ref` becomes one object property triple.

Example:
- `created_by_ref`
- `source_ref`
- `target_ref`
- `sighting_of_ref`

### Multi-reference
Any STIX field ending in `_refs` becomes multiple object property triples.

Example:
- `object_marking_refs`
- `where_sighted_refs`
- `object_refs`

### Rule
Each reference should point to the IRI derived from the referenced STIX ID.

---

## Local extension vocabulary (`cti:`)

The following local extension terms are recommended for v1:

### Classes
- `cti:Vulnerability`
- `cti:Opinion`
- `cti:Note`

### Object properties
- `cti:hasMember`
- `cti:createdBy`
- `cti:objectMarking`
- `cti:referencesObject`
- `cti:sightingOf`
- `cti:whereSighted`
- `cti:observedDataRef`
- `cti:observedObject`
- `cti:killChainPhase`

### Datatype properties
- `cti:stixCreated`
- `cti:stixModified`
- `cti:stixPattern`
- `cti:patternType`
- `cti:indicatorType`
- `cti:identityClass`
- `cti:label`
- `cti:alias`
- `cti:goal`
- `cti:objective`
- `cti:role`
- `cti:sector`
- `cti:primaryMotivation`
- `cti:secondaryMotivation`
- `cti:sophistication`
- `cti:resourceLevel`
- `cti:isFamily`
- `cti:malwareType`
- `cti:toolType`
- `cti:firstSeen`
- `cti:lastSeen`
- `cti:firstObserved`
- `cti:lastObserved`
- `cti:numberObserved`
- `cti:sightingCount`
- `cti:published`
- `cti:reportType`
- `cti:definitionType`
- `cti:definition`
- `cti:specVersion`
- `cti:revoked`
- `cti:externalReference`

---

## Python implementation rules

### Minimum converter behavior
The Python converter should:

1. load STIX JSON,
2. detect whether the root is a bundle,
3. iterate through contained objects,
4. create one RDF subject per STIX object,
5. assign `rdf:type` using the type mapping table,
6. add common properties,
7. handle `bundle`,
8. handle `relationship`,
9. preserve unresolved/ambiguous semantics in `cti:` properties,
10. serialize to `.ttl`.

### Initial implementation priority
Implement first:

1. `bundle`
2. `relationship`
3. `identity`
4. `threat-actor`
5. `attack-pattern`
6. `campaign`
7. `malware`
8. `indicator`
9. `report`
10. `observed-data`
11. `sighting`

---

## Example transformation pattern

### Input STIX
```json
{
  "type": "relationship",
  "id": "relationship--123",
  "relationship_type": "uses",
  "source_ref": "campaign--1",
  "target_ref": "attack-pattern--1"
}
```

### Output RDF
```ttl
ex:relationship--123
    a core:Relationship ;
    core:source ex:campaign--1 ;
    core:target ex:attack-pattern--1 ;
    core:kindOfRelationship "uses" .
```

---

## Non-goals for v1

The following are intentionally out of scope for the first implementation:

- full semantic decomposition of STIX pattern expressions,
- perfect native UCO predicate mapping for every STIX relationship type,
- complete deep modeling of all SCO object internals,
- ontology-level inference optimization,
- SHACL validation layer.

These can be added in v2 after the first full conversion pipeline works.

---

## Validation checklist

Each converted TTL file must pass:

- RDF parse success
- stable subject IRI creation from STIX IDs
- no broken object references for known IDs
- valid datetime literals where used
- relationship nodes with both source and target
- bundle nodes with membership triples
- indicators retaining original pattern strings
- successful load into Virtuoso

---

## Versioning policy

- `v1`: conservative conversion, stable triples, local `cti:` extensions allowed
- `v2`: refined UCO-native predicates where verified
- `v3`: deeper observable/SCO modeling and validation rules

---

## Final implementation stance

This mapping intentionally favors:

- correctness over aggressiveness,
- traceability over elegance,
- stable RDF generation over speculative ontology alignment.

The converter should first be able to process the STIX OASIS examples reliably.
Refinement comes after successful end-to-end conversion and Virtuoso loading.
