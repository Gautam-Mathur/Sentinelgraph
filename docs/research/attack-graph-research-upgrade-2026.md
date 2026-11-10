# SentinelGraph Research Upgrade: Attack-Graph Intelligence Beyond Static Paths

**Research cut:** 10 November 2026  
**Repository baseline reviewed:** `main` at `ff24df635d76c7ec8c5a3849bbddee86b1ddb526`  
**Scope:** Research and architecture direction only. This document does not describe an implemented feature or propose silently changing runtime behaviour.

---

## 1. Executive conclusion

SentinelGraph already has a useful evidence-backed topology and path-analysis foundation: typed assets, services, identities and groups; ten controlled relationship types; observed, inferred and analyst-asserted facts; temporal validity fields; bounded BFS/Dijkstra path enumeration; explicit transition preconditions; independent reachability verification; sandbox remediation simulation; and a heuristic priority score.

The next meaningful research step is not to add more edge types or another score. It is to evolve the analytical model from **static relationship traversal** toward **stateful, evidence-grounded attack planning** while preserving the existing graph as the system-of-record for observed topology and provenance.

The literature supports five connected research directions:

1. **Stateful action planning:** represent attacker actions with preconditions and effects, so capabilities gained at one step can be consumed by later steps.
2. **AND/OR and non-monotonic dependencies:** express compound requirements, alternative routes, and state changes that remove previously available capabilities.
3. **Incremental and progressive analysis:** recompute only affected analysis regions where safe, while keeping exact reachability separate from sampled estimates.
4. **Defender optimization:** choose remediation actions under cost, availability, ownership and change-window constraints; do not call a bounded candidate set a global minimum.
5. **Calibrated risk and trustworthy evidence:** keep ranking, severity, exploit likelihood and environmental impact separate; make every derived claim traceable to source evidence and model versions.

**Recommended target:** retain PostgreSQL, NetworkX and the current modular-monolith architecture initially. Add a versioned planning model and a planner adapter as a separate domain subsystem. Do not migrate to a graph database or introduce an autonomous execution agent as the first step.

---

## 2. Baseline assessment: what exists and what it does not yet prove

This section describes the repository inspected at the research cut. It is not a certification of production readiness. The baseline includes the merged corrections to explicit administrative-gate evaluation and case-insensitive CVE remediation state. The post-merge CI run passed backend, frontend and Compose checks; the backend suite reported 73 passed and one warning.

| Area | Repository baseline | Research implication |
|---|---|---|
| Graph entities | Asset, Service, Identity and Group node kinds | A good foundation for mixed infrastructure and identity analysis |
| Relationships | Ten controlled relationship types with endpoint validation | Useful topology model, but pairwise edges cannot express every compound action naturally |
| Evidence | Observed, inferred and analyst-asserted facts; confidence; provenance; validity bounds; suppression | Preserve the epistemic distinction; add claim derivation and source lineage at finer granularity |
| Traversal | Bounded BFS and Dijkstra enumeration with caps and timeouts | Candidate path enumeration is not a proof of total path count |
| Preconditions | Three-valued true / false / unknown evaluation for explicit and built-in relationship conditions | Useful start, but a richer logical language and action effects are needed for sequence-dependent capabilities |
| Reachability | Independent BFS verifier for possible and confirmed reachability, including hop-bounded and unbounded views | Retain exact reachability as a separate primitive |
| Remediation | Deep-copy sandbox transformations and residual reachability checks | Extend from cut candidates to constrained action portfolios |
| Scoring | Versioned 0–100 prioritization heuristic | Continue describing it as a heuristic; do not relabel it as probability |
| Import | Offline scanner, topology, identity and cloud-export parsers with staged approval | Extend through adapters; do not bind the analytical core to one vendor format |
| Governance | Tenant isolation, RLS, role checks, audit and retention controls | Planning inputs, outputs and derived evidence must inherit tenant and authorization boundaries |

### Documentation inconsistencies discovered

The README still describes the cut-set solver using phrases such as “minimum 2-edge hitting sets” and “greedy minimum hitting sets.” The newer analytical contract correctly distinguishes a model-verified candidate cut from a proven global minimum. The research roadmap assumes the more conservative contract: **candidate cut, verification status, and minimum-optimality proof are separate properties**. These descriptions should be reconciled before making external performance or optimality claims.

The test plan documents a browser E2E suite, while the main CI workflow currently runs unit, integration, security and performance tests plus frontend checks and Compose validation. Browser E2E should be reported separately unless it is added to the required CI gates.

---

## 3. Research direction A — stateful attack planning

### Why this matters

A static graph answers: “Is there a chain of currently modelled relationships between these nodes?” A stateful planner answers a richer question: “Given an initial attacker state, which sequence of abstract actions could reach the goal, and what facts become true or false after each action?”

This distinction matters for identity and privilege chains. A transition that obtains a service credential should produce a capability in the simulated state. A later transition that assumes a role should require that capability, the right trust relationship, a valid token context, and the relevant resource policy. The second action must not be accepted merely because two independent edges happen to be adjacent in a graph.

Planning-based attack-path research has represented attack knowledge and topology in PDDL, then delegated plan search to an AI planner. Wang et al. combine a graph data model with PDDL and partition device reachability graphs to reduce the size of planning problems. The paper also reports a multithreaded path-enumeration workflow and discusses memory trade-offs as concurrency increases. [Wang et al., 2021](https://doi.org/10.1155/2021/1444182).

The 2025 SPEAR framework is especially relevant. It uses AI planning and an Attack-Connectivity Graph represented as a hypergraph, supports incomplete information, human-in-the-loop hardening analysis, and explicitly discusses non-monotonic behaviour. Its authors position the hypergraph as a way to represent dependencies among vulnerabilities and network connectivity together. [Podder et al., 2025, SACMAT](https://doi.org/10.1145/3734436.3734451) · [arXiv record](https://arxiv.org/abs/2506.01227).

### Proposed model

Keep the current evidence graph. Introduce a separate, versioned planning layer with these concepts:

| Concept | Purpose |
|---|---|
| Planning fact | A typed proposition about the environment or simulated actor, such as a credential being available, a service being reachable, or a role being enabled |
| Action schema | An abstract transition with parameters, preconditions, add effects and delete effects |
| Initial state | Facts supported by the approved assessment snapshot |
| Goal expression | The target condition, such as access to a protected asset or administrative control over a resource |
| Plan | An ordered sequence of abstract actions with state snapshots and evidence references |
| Planner result | Found, not found under a complete search, bounded/unknown, or unsupported model state |

Each action schema should declare:

- Required facts and their logical form: all-of, any-of and negation.
- Facts added when the abstract action succeeds.
- Facts removed or invalidated when the abstract action succeeds.
- Preconditions that are unknown because evidence is missing.
- Required evidence references and the rule/model version that produced the action.
- Cost, duration or operational attributes if used for defender analysis.
- A clear statement that the action is a modelled transition, not a live exploit or execution instruction.

Example at the semantic level:

- Initial facts: a host is reachable; a vulnerability is recorded as open; a service identity is associated with the host.
- Action: obtain a workload identity capability.
- Preconditions: the path is reachable, the vulnerability state is open, and the required privilege condition is satisfied.
- Add effect: the simulated actor possesses the workload identity.
- Next action: request a role session.
- Preconditions: the actor possesses the identity, trust permits the relationship, and the resource policy allows the session.
- Add effect: the actor has the role capability.
- Goal: the actor can reach the protected resource under the modelled policy.

This makes the causal meaning explicit. It also makes it possible to explain exactly which earlier action produced a capability required later.

### Architecture recommendation

Use an internal typed action model first. Do not make PDDL a runtime dependency in the first prototype.

A practical sequence is:

1. Define a small typed action schema and finite fact vocabulary.
2. Build a deterministic state-transition function.
3. Implement a bounded best-first or breadth-first planner for small graphs.
4. Compare planner results against exhaustive state-space enumeration on tiny synthetic scenarios.
5. Add a PDDL exporter/importer or external planner adapter only after the internal semantics are stable.

The existing NetworkX graph remains the evidence/topology projection for the UI. A plan step should link to the evidence edge(s), finding(s), policy record(s), and action-rule version that justify it.

### Critical modelling issue: non-monotonic effects

A monotonic model only adds capabilities. Enterprise systems are not monotonic. Patching a CVE, revoking a token, disabling a role, changing a firewall rule, expiring a session, or removing a group membership can make a previously possible transition impossible.

The planning state therefore needs both add and delete effects. It must also represent time-bounded facts: a credential may be valid now but expire; a finding may be open in one evidence snapshot and patched in a later one. Do not treat a state transition as permanent without a validity interval or explicit lifecycle rule.

---

## 4. Research direction B — AND/OR dependencies and uncertainty

### From a flat list to logical expressions

Many enterprise access conditions are compound:

- device compliance AND user authentication AND resource authorization;
- possession of a certificate OR a workload token;
- valid trust AND an accepted issuer AND the correct audience;
- network reachability AND service state AND the applicable policy decision.

Representing every condition as an independent edge risks losing the fact that several predicates jointly enable one action. A hypergraph, bipartite fact/action graph, or typed expression tree can represent this more faithfully.

Recommended initial logical language:

- ALL: every child condition must hold.
- ANY: at least one child condition must hold.
- NOT: the condition must not hold.
- FACT: a typed state predicate with value, source, timestamp and validity.
- UNKNOWN: the evidence cannot currently determine the predicate.

The logic needs explicit semantics for unknown values. Do not silently make unknown equivalent to true or false. Preserve two analysis views:

- **Possible view:** unknown conditions may be assumed satisfiable, but every such assumption is visible.
- **Confirmed view:** only conditions supported as true are traversable.
- **Blocked view:** any mandatory condition known false blocks the action.

For compound conditions, three-valued evaluation must be formally specified and tested. For example, ALL(false, unknown) is false; ALL(true, unknown) is unknown; ANY(true, unknown) is true; ANY(false, unknown) is unknown. These rules should be documented as a contract rather than reimplemented ad hoc by each module.

### Zero Trust implications

NIST SP 800-207 says zero trust should not grant implicit trust based only on network location or asset ownership; authentication and authorization of the subject and device are discrete functions before establishing a resource session. This supports modelling resource access as a dynamic policy decision involving identity, device, application and resource context—not as a subnet adjacency alone. [NIST SP 800-207](https://doi.org/10.6028/NIST.SP.800-207).

**Product implication:** add policy decision facts and identity/device posture to the planning vocabulary. Do not equate “network connected” with “authorized to access the resource.”

---

## 5. Research direction C — scalable and adaptive analysis

### Exact and approximate analysis must remain separate

The 2025 StatAG/SteerAG work proposes progressive attack-graph analysis using weighted path sampling and statistical stability measures. It enables analysts to query partial attack-graph results before complete generation, and steers generation toward the analyst's query. The paper evaluates convergence using Kolmogorov–Smirnov distances and describes approximation/stability thresholds in its own experimental settings. It also notes that statistical stability itself has computational cost and introduces an approximation to reduce it. [Palma, Cicimurri & Angelini, 2025](https://doi.org/10.1007/s10207-025-01125-w).

The paper's ground-truth experiments include configurations up to 20 hosts and 50 vulnerabilities per host, where complete enumeration took hundreds of hours in the authors' setup. Those figures explain the motivation; they are not a general benchmark for SentinelGraph or every network. [Experimental configuration](https://link.springer.com/article/10.1007/s10207-025-01125-w).

For SentinelGraph, use three distinct outputs:

| Analysis mode | Candidate method | Permitted claim |
|---|---|---|
| Exact reachability | Independent BFS or equivalent complete verifier over the declared finite model | Whether a route exists under the chosen model, filters and state semantics |
| Explainable paths | Bounded top-k path or plan enumeration | The returned candidate plans, with truncation and search limits disclosed |
| Progressive analytics | Weighted sampling and query-directed exploration | Estimated distributions or rankings with convergence/uncertainty metadata |

A sample that found no route is not proof that no route exists. A sampled path count is not a total path count. Progressive analytics must never replace exact reachability or a complete solver when the UI makes a binary security claim.

### Incremental updates

Two 2026 publications point to a current research direction around local updates rather than full recomputation:

- ThreatWeaver describes attack steps as triggerable attack functions with input/output semantics, and updates only when their conditions are met. The paper frames this as evidence-driven incremental inference. [Computers & Security, October 2026](https://doi.org/10.1016/j.cose.2026.104982).
- DynAssetRank describes a dynamic risk framework combining CVE and non-CVE weaknesses with localized recomputation and global calibration. [IEEE TDSC, 2026](https://doi.org/10.1109/TDSC.2026.3687798).

For both 2026 papers, this review relied on the accessible bibliographic/abstract material; it did not independently reproduce the reported performance claims or inspect the full experimental methodology. Treat them as research leads, not validated engineering targets.

### SentinelGraph implementation direction

Build an incremental dependency index before attempting a fully streaming planner:

1. Record which facts, edges, action schemas and score components depend on each imported observation.
2. When an approved evidence delta arrives, compute the affected dependency region.
3. Invalidate only the derived plans, reachability summaries and scores whose dependency set intersects that region.
4. Recompute the affected region exactly where feasible.
5. Fall back to a full rebuild whenever dependency completeness is uncertain.
6. Record the input snapshot, invalidation set, engine version and recomputation status.

Graph partitioning can help plan search, but the partition boundary must preserve cross-partition reachability and all boundary facts. The IT/OT PDDL paper partitions device reachability graphs and reports a memory cost for multithreaded enumeration; parallelism should therefore be benchmarked for both latency and memory, not just wall-clock time. [Wang et al., 2021](https://doi.org/10.1155/2021/1444182).

---

## 6. Research direction D — remediation as constrained defender optimization

A verified candidate cut and an optimal remediation portfolio are different results.

Jha, Sheyner and Wing formally relate attack-graph minimization to the minimum hitting-set problem and provide a greedy algorithm with provable bounds. Their work also models attack-graph reliability using Markov Decision Processes. The hitting-set result is important because it exposes the combinatorial nature of choosing controls that cover every successful attack path. [CMU technical report](https://www.cs.cmu.edu/afs/cs/project/calder/www/tr02-109.html).

Durkota et al. model a defender with limited resources facing a multi-stage strategic attacker. Their attack-graph-game approach translates the graph to an MDP and uses policy search and pruning to address computational complexity. This is a different problem from simply deleting the smallest number of graph edges. [IJCAI 2015](https://www.ijcai.org/proceedings/2015/80).

A later dynamic-network hardening study explicitly considers fixed budgets, availability, performance degradation and non-patchable vulnerabilities as constraints in multi-objective security optimization. [Enoch et al., 2022](https://doi.org/10.1016/j.comnet.2022.108864).

### Recommended remediation model

Represent each available defender action with:

- direct implementation cost or effort;
- change-window and deployment constraints;
- service availability impact;
- operational risk and rollback requirements;
- affected assets, identities, policies and graph facts;
- expected change to action preconditions and effects;
- residual route/goal reachability after the action;
- provenance and owner approval requirements.

Then optimize a portfolio under an explicit budget and constraints.

Suggested objective dimensions:

1. eliminate or reduce reachability to critical goals;
2. reduce modelled attacker options and privilege gained;
3. preserve service availability;
4. minimize cost and operational disruption;
5. avoid fragile solutions that depend on uncertain or stale evidence.

Do not collapse these into an unexplained scalar too early. Start with a Pareto frontier or an explicitly weighted objective whose weights are visible and configurable.

### Output labels that should remain distinct

- **Candidate cut:** an action/edge set generated by a bounded heuristic.
- **Model-verified cut:** the declared model has no remaining possible goal-reaching plan after the proposed transformation and the verifier completed.
- **Minimum cut proven:** optimality has been proven for the formal problem definition and constraints.
- **Budget-feasible portfolio:** the chosen set satisfies stated cost and operational constraints.
- **Operationally validated:** independent post-change evidence confirms the intended control is deployed and effective.

A model-verified cut does not prove a live environment is safe. A minimum hitting set over enumerated paths does not automatically remain optimal when actions have shared effects, non-linear costs, availability constraints or stateful side effects.

---

## 7. Research direction E — risk scores, calibrated likelihood and impact

The existing 0–100 score should remain a deterministic remediation-priority heuristic. The next research step should not be to rename it as a probability.

Use distinct fields for:

| Measure | Meaning |
|---|---|
| Priority heuristic | Relative order for analyst triage under the defined SentinelGraph scoring contract |
| Vulnerability severity | Technical severity classification or CVSS vector/base score |
| Exploit likelihood | A probability estimate with a defined outcome and time horizon, when a calibrated model is available |
| Observed exploitation | Evidence that exploitation has been reported or confirmed |
| Environmental exposure | Whether the affected product/asset is present and reachable in this tenant's environment |
| Business impact | Consequence if the relevant goal is achieved |

FIRST defines EPSS as a data-driven estimate of the probability that exploitation activity for a published CVE will be observed in the wild in the next 30 days. FIRST also states that EPSS is not a complete risk score: it does not know the local asset, compensating controls or business impact. [EPSS FAQ](https://www.first.org/epss/faq.html) · [How EPSS works](https://www.first.org/epss/how-it-works.html).

A particularly important implementation constraint: FIRST explicitly warns that multiplying EPSS probability by CVSS Base severity does not produce a meaningful probability or risk measure, because CVSS Base is an ordinal severity score and EPSS is a calibrated probability. [FIRST EPSS FAQ](https://www.first.org/epss/faq.html).

NISTIR 7788 describes propagating likelihoods through probabilistic attack graphs to reason about the composition of multiple attack steps and enterprise-level risk. This is a more principled direction for path likelihood than multiplying arbitrary per-edge confidence values. [NISTIR 7788](https://doi.org/10.6028/NIST.IR.7788).

### Calibration requirements before shipping a probability

A future path-likelihood model needs:

- a precise event definition: exploitation attempt, successful compromise, or observation of exploitation;
- a defined time horizon;
- representative, timestamped labels;
- explicit handling of missing and censored observations;
- conditional dependencies and common-cause factors;
- out-of-time validation;
- calibration plots and proper scoring rules such as Brier score or log loss;
- precision-recall and coverage/effort analysis for highly imbalanced outcomes;
- drift monitoring and model-version retention.

Until the data and evaluation programme exist, show component signals separately and do not expose a synthetic “probability of breach.”

---

## 8. Evidence provenance and interoperability

SentinelGraph already records evidence provenance and uses staged ingestion. The next upgrade should give every derived claim a first-class lineage record:

- source entity/record and immutable content hash;
- parser and normalizer version;
- collection time and observation time;
- transformation activity and rule version;
- responsible source system or analyst;
- derived claim identifier;
- derivation links from source evidence to normalized fact, action schema, plan and recommendation.

The W3C PROV Data Model is a useful conceptual foundation. It models entities, activities, agents, derivations, responsibility and bundles, allowing consumers to assess quality, reliability and trustworthiness. [W3C PROV-DM Recommendation](https://www.w3.org/TR/prov-dm/).

For threat knowledge interoperability, MITRE ATT&CK uses STIX 2.1 objects and relationship objects, with a documented schema and validation layers. SentinelGraph should map external technique, software, group, mitigation and analytic references through an adapter rather than treating ATT&CK techniques as observed infrastructure relationships. A technique reference is threat knowledge; it is not proof that the technique occurred in the tenant. [MITRE ATT&CK specification](https://mitre-attack.github.io/attack-data-model/schemas/) · [MITRE ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data).

Recommended rule: separate three namespaces in the product model:

1. **Observed environment facts** — what the imported evidence says about this tenant.
2. **Derived analytical claims** — what SentinelGraph inferred from those facts under a specific rule version.
3. **External threat knowledge** — ATT&CK, CVE, KEV, EPSS and other public knowledge objects.

They may be linked, but they must not be conflated.

---

## 9. Proposed target architecture

Keep the existing service boundaries. Extend the pure domain layer into five cooperating components:

| Component | Responsibility | Required guarantee |
|---|---|---|
| Evidence graph | Versioned topology, identities, services, findings, policy and provenance | Every fact is tenant-scoped, time-aware and traceable |
| State compiler | Compiles an approved evidence snapshot into facts and action schemas | Deterministic output with compiler/rule version |
| Planning engine | Searches action sequences from initial state to goal state | Explicit search bounds, state semantics and completeness status |
| Analysis engine | Exact reachability, bounded explainable plans, progressive analytics and incremental invalidation | Approximate results never masquerade as exact proofs |
| Defender optimizer | Evaluates remediation portfolios and constraints in sandbox states | Every recommendation includes assumptions, cost model and residual verification |

The UI should present evidence, assumptions, plan steps, state changes, and verification status separately. The existing Cytoscape graph can show infrastructure relationships; a plan inspector should show action preconditions and the state gained/lost at each step.

Do not introduce a graph database solely because the graph is central to the product. First measure the current PostgreSQL + NetworkX workflow against expected tenant scale, memory, ingestion latency, path-search latency and concurrent jobs. A storage migration is justified only when measured query or operational constraints require it.

---

## 10. Research and validation programme

Before implementing the stateful engine, define a benchmark suite that can act as an independent correctness oracle.

### A. Formal semantics tests

- Enumerate all states for tiny action domains and compare planner results to exhaustive search.
- Test ALL/ANY/NOT evaluation across true, false and unknown inputs.
- Verify add effects and delete effects, including revocation, expiry, patching and policy changes.
- Verify that each plan step's preconditions are satisfied by the state produced by earlier steps.
- Verify determinism for equal initial states, goals, action libraries and versioned inputs.

### B. Graph and planner differential tests

- Compare exact BFS reachability with exhaustive enumeration on small finite graphs.
- Compare planner reachability with the same exhaustive state-space oracle.
- Include cycles, parallel edges, multiple starts/goals, disconnected components and cross-partition boundaries.
- Inject missing, contradictory, stale and time-expired evidence.
- Confirm that candidate caps and timeouts produce an explicit incomplete status, never a false “no route” conclusion.

### C. Remediation correctness tests

- Verify each transformation's declared add/delete effects.
- Recompute plans after each action and after action combinations.
- Confirm that a portfolio does not claim success while a possible goal-reaching plan remains.
- Check action costs, availability constraints, excluded maintenance windows and rollback constraints.
- Test exact optimality only on small instances where an exhaustive or exact solver can prove it.

### D. Scale and progressive-analysis tests

Benchmark multiple graph shapes: chain, tree, mesh, scale-free/power-law, identity-heavy, cloud-policy-heavy and mixed enterprise topologies.

Report:

- node/edge/fact/action counts;
- number of grounded action instances;
- states explored and pruned;
- exact reachability latency;
- top-k plan latency;
- memory high-water mark;
- incremental update latency and affected-region size;
- sample count and convergence indicators for progressive estimates;
- quality versus exact ground truth on tractable fixtures.

The 2025 progressive-graph paper uses distribution convergence and stability to assess partial results. SentinelGraph should independently define its own convergence contract and evaluate it on its own synthetic and representative fixtures; do not copy thresholds from the paper as universal guarantees.

### E. Risk-model validation

For any future probability output, define the event, time horizon and data collection protocol before model selection. Evaluate on temporally held-out data; compare with base-rate and simple baselines; report calibration and ranking quality separately. Do not use accuracy alone on rare exploitation outcomes.

### F. Security and governance validation

The planning layer must inherit tenant isolation and RBAC. Ensure that:

- one tenant cannot reference another tenant's plan, evidence or model;
- imported content cannot inject executable action schemas;
- analyst assertions remain distinct from observations;
- model and external knowledge versions are pinned for reproducibility;
- exports include derivation metadata but never expose secrets;
- long-running planning jobs re-check authorization before execution;
- all simulations remain non-executing and modelled-only.

---

## 11. Prioritised research roadmap

| Priority | Workstream | Research deliverable | Exit criterion |
|---|---|---|---|
| P0 | Formal state/action semantics | Action schema, fact vocabulary, unknown semantics and state lifecycle specification | Tiny scenarios have a complete exhaustive oracle |
| P0 | Stateful planner prototype | Minimal planner and evidence-to-action compiler | Multi-step capability acquisition works without relying on unrelated edge adjacency |
| P1 | AND/OR hypergraph model | Formal condition expressions and non-monotonic effects | Compound policy gates and delete effects are represented and tested |
| P1 | Provenance lineage | Claim-to-evidence derivation model aligned conceptually with PROV-DM | Every plan step can be traced to its inputs and rule versions |
| P1 | Remediation portfolio optimization | Cost/availability-aware solver comparison | Candidate, feasible and proven-optimal labels are distinct |
| P2 | Incremental recomputation | Dependency index and safe invalidation strategy | Incremental output equals full recomputation on differential tests |
| P2 | Progressive analysis | Sampling and convergence indicators | Estimates have measured error against exact ground truth on tractable graphs |
| P2 | Interoperability | ATT&CK/STIX and refreshed EPSS/KEV adapters | External knowledge is versioned and never mistaken for tenant observation |
| P3 | Calibrated risk | Statistical model and outcome data programme | Out-of-time calibration and drift criteria are met before probability claims ship |

### Explicit non-goals for the next research cycle

- No live exploitation or automated offensive execution.
- No automatic patching or infrastructure changes.
- No replacement of exact reachability with sampling.
- No claim of global minimum remediation without an optimality proof.
- No graph-database migration without benchmark evidence.
- No “breach probability” label for the current heuristic score.
- No machine-learning model inserted into the trust path without calibration, explainability and drift controls.

---

## 12. Research source register

Sources below are ordered by direct relevance to the proposed architecture. “Full text reviewed” means the accessible publication text was inspected; “abstract/bibliographic review” means the accessible summary was used and the reported experiments were not independently reproduced.

| Source | Contribution relevant to SentinelGraph | Review level |
|---|---|---|
| Wang et al., 2021, [planning-based IT-to-OT attack-path discovery](https://doi.org/10.1155/2021/1444182) | PDDL + graph model, reachability partitioning, parallel planning | Full text reviewed |
| Podder et al., 2025, [SPEAR](https://doi.org/10.1145/3734436.3734451) | PDDL planning, attack-connectivity hypergraphs, incomplete information, non-monotonicity, human-in-the-loop hardening | Paper landing page and arXiv abstract/selected text reviewed |
| Palma et al., 2025, [Progressive attack graph / StatAG / SteerAG](https://doi.org/10.1007/s10207-025-01125-w) | Weighted path sampling, convergence indicators, query-steered progressive analysis | Full text reviewed |
| Jha, Sheyner & Wing, 2002, [Minimization and Reliability Analyses of Attack Graphs](https://www.cs.cmu.edu/afs/cs/project/calder/www/tr02-109.html) | Minimum hitting-set formulation, greedy bounds, MDP reliability | Abstract/technical-report page reviewed |
| Durkota et al., 2015, [Optimal Network Security Hardening Using Attack Graph Games](https://www.ijcai.org/proceedings/2015/80) | Defender-attacker game, limited-resource hardening, MDP and pruning | Proceedings paper page reviewed |
| Singhal & Ou, 2011, [NISTIR 7788](https://doi.org/10.6028/NIST.IR.7788) | Probabilistic attack-graph likelihood propagation and mitigation analysis | NIST publication page reviewed |
| FIRST, [EPSS FAQ](https://www.first.org/epss/faq.html) and [methodology](https://www.first.org/epss/how-it-works.html) | Calibrated 30-day CVE exploitation probability, population limits, calibration and misuse cautions | Official methodology reviewed |
| W3C, [PROV-DM](https://www.w3.org/TR/prov-dm/) | Entity/activity/agent/derivation provenance model | Recommendation reviewed |
| MITRE, [ATT&CK Data Model](https://mitre-attack.github.io/attack-data-model/schemas/) | STIX 2.1 object and relationship interoperability | Official schema reviewed |
| NIST, [SP 800-207 Zero Trust Architecture](https://doi.org/10.6028/NIST.SP.800-207) | Subject/device authentication, resource-centred dynamic authorization, no implicit network trust | Official standard abstract and publication record reviewed |
| Enoch et al., 2022, [multi-objective dynamic-network hardening](https://doi.org/10.1016/j.comnet.2022.108864) | Budget, availability, performance and non-patchable vulnerability constraints | Abstract/metadata review |
| ThreatWeaver, 2026, [evidence-driven incremental attack-graph generation](https://doi.org/10.1016/j.cose.2026.104982) | Triggerable attack functions and local updates on condition-satisfying inputs | Abstract/metadata review only |
| DynAssetRank, 2026, [dynamic risk assessment with ATT&CK modelling](https://doi.org/10.1109/TDSC.2026.3687798) | Non-CVE behaviours and localized risk recomputation | Abstract/metadata review only |
| [Survey: Automatic generation of attack trees and attack graphs](https://doi.org/10.1016/j.cose.2023.103602) | Taxonomy of generation methods and open research challenges | Abstract/secondary page review |

---

## 13. Decision summary

The recommended research direction is a **stateful, evidence-grounded planning engine over the existing graph**, supported by formal compound preconditions, non-monotonic state changes, independently verified reachability, incremental analysis and constrained defender optimization.

That approach builds on what SentinelGraph already does well instead of replacing its foundations. More importantly, it gives the product a defensible analytical contract:

- evidence describes what is known;
- state compilation describes what that evidence implies;
- planning describes what sequences are possible under declared assumptions;
- reachability verification describes what the formal model proves;
- optimization describes which defensive choices best satisfy explicit constraints;
- probability is introduced only when it is empirically calibrated.

That is the research path most likely to make SentinelGraph materially more rigorous and differentiated without turning it into an opaque autonomous agent.
