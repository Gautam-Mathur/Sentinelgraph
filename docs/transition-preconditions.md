# Transition preconditions

SentinelGraph distinguishes **relationship evidence** from **whether a transition is
currently feasible**. Edge confidence describes evidence strength. It must not be used
as a proxy for firewall permission, a live credential, vulnerability state, MFA, PAM,
or other operational gates.

## Three-valued evaluation

Every evaluated prerequisite is reported as one of:

- `true`: the supplied evidence explicitly satisfies the prerequisite.
- `false`: the supplied evidence explicitly contradicts the prerequisite. The edge is
  not traversable in either path-search mode.
- `unknown`: the available evidence cannot determine the prerequisite.

Path search defaults to `allow_unknown_preconditions=True`. This is the **possible /
conditional hypothesis** view: unknown requirements remain in the candidate route and
are attached to the path as explicit assumptions. Set it to `False` for a
**confirmed-only** graph view; that view traverses only edges whose evaluated
prerequisites are all true.

An absent property is unknown, never implicitly true. A false property blocks the edge.
Precondition results are included in path-step explanation traces and the search
determinism hash includes the unknown-precondition policy.

## Explicit edge metadata schema

A relationship export can place a list of conditions in `metadata.preconditions`.
After import this is stored in `GraphEdge.edge_metadata["preconditions"]`.

Example:

```json
{
  "preconditions": [
    {
      "id": "acl-prod-app-db",
      "kind": "network_reachable",
      "field": "network_reachable",
      "expected": true,
      "reason": "Approved route and firewall policy permit app-to-db traffic.",
      "evidence_ref": "firewall-export:rule-104"
    },
    {
      "id": "mfa-admin-gate",
      "kind": "mfa_gate",
      "status": true,
      "reason": "MFA challenge satisfied for the administrative session.",
      "evidence_ref": "idp-event:evt-8801"
    }
  ]
}
```

Each item supports either:
- `status`: a boolean outcome backed by the source evidence; or
- `field` plus optional `expected`: a dotted path into the edge metadata and the
  value that must match. When `expected` is omitted, it defaults to boolean `true`.

Malformed conditions, missing fields, and unrecognised states produce `unknown`.
Do not attach an explicit true status unless an evidence record or a documented
analyst assertion supports it.

## Built-in relationship fields

Built-in relationship checks are evaluated alongside explicit `preconditions`.
An evidence-backed typed explicit gate (for example, `mfa_gate`) may resolve an
otherwise unknown corresponding gate. It cannot override a known-false built-in
observation or bypass the mandatory administrative-right and CVE checks.

Known relationship types use these metadata fields:

| Relationship | Required metadata | Meaning when missing |
|---|---|---|
| `CONNECTS_TO`, `EXPOSES` | `network_reachable: true` and/or `acl_action: allow/permit/accept` | Unknown |
| `CAN_ADMINISTER` | `admin_enabled` (or `standing_admin_enabled`); when `pam_enforced=true`, `pam_approval_granted`; when `mfa_required=true`, `mfa_satisfied` | Unknown |
| `MEMBER_OF` | `membership_active: true` | Unknown |
| `HAS_ROLE` | `credential_available: true` | Unknown |
| `TRUSTS` | `trust_accepts_token: true` | Unknown |
| `RUNS_SERVICE` | `service_listening: true` | Unknown |
| Any edge with `requires_cve` | `vulnerability_status[CVE-ID]` | Unknown |

When both `network_reachable` and `acl_action` are supplied, both are evaluated;
contradictory evidence (for example, reachability true with an ACL deny) blocks the
transition. An empty `preconditions` list does not suppress built-in relationship
checks.

For CVE prerequisites, the evaluator reads `vulnerability_status` and
`remediated_cves` from the relationship and from its source/target node metadata.
`requires_cve_on: "source"` or `"target"` can limit endpoint lookup to one side.
Assessment graph construction carries per-CVE states and open-finding counts from
the Finding records into asset-node metadata.

`open`, `unpatched`, `vulnerable`, and `confirmed` mean
the vulnerability remains a prerequisite. `patched`, `mitigated`, `remediated`,
`fixed`, and `closed` make that prerequisite false and block the transition.

## CVE patch simulation semantics

A `PATCH_VULNERABILITY` sandbox transform requires a CVE identifier and a matching
CVE-specific reference. Asset nodes receive per-CVE state from their open findings;
a relationship can also establish a reference through `requires_cve`. An asset ID and
an aggregate open-CVE count alone are not enough to patch an arbitrary CVE.

For matching node/edge scope the transform sets
`vulnerability_status[CVE-ID] = "patched"` and records the CVE in
`remediated_cves`. A matching node's open-finding count is decremented by the number
of open findings recorded for that CVE (never below zero). Edge confidence is
unchanged: confidence measures the strength of relationship evidence and is
independent of vulnerability remediation.

This is a sandbox model only. A later evidence import must establish whether the
vulnerability is actually fixed in the environment.

## Interpretation limits

A path found with unknown prerequisites is a **possible conditional path**, not proof
that every operational gate is currently satisfied. A path found in confirmed-only
mode has prerequisites represented as true by the available metadata, but this still
does not prove exploitation or a breach.

The BFS reachability verifier reports possible and confirmed reachability separately,
and also reports both unbounded structural reachability and reachability within the
configured hop budget. A model-verified cut means no possible route remains in this
sandbox graph under its declared constraints; it is not proof of live remediation or
global minimum-cut optimality.
