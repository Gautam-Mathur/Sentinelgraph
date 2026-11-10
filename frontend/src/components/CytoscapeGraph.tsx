import React, { useEffect, useId, useMemo, useRef, useState } from "react";
import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import type { EdgeBlastRadius, GraphEdge, GraphNode } from "../types/api";
import { CriticalityBadge, ProvenanceBadge } from "./Badges";

interface CytoscapeGraphProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  highlightedPathNodeKeys?: string[];
  highlightedPathEdgeIds?: string[];
  cutEdgeIds?: string[];
  edgeBlastRadius?: Record<string, EdgeBlastRadius>;
  activeOverlayTitle?: string;
  activeCutTitle?: string;
  onClearOverlay?: () => void;
  onSelectNode?: (node: GraphNode) => void;
  onSelectEdge?: (edge: GraphEdge) => void;
  onSimulateEdgeCut?: (edge: GraphEdge, blast?: EdgeBlastRadius) => void;
  canvasHeight?: number;
}

const RELATION_TYPES = [
  "ALL",
  "HOSTS",
  "CONNECTS_TO",
  "RUNS_SERVICE",
  "EXPOSES",
  "DEPENDS_ON",
  "MEMBER_OF",
  "HAS_ROLE",
  "CAN_ADMINISTER",
  "TRUSTS",
  "OWNS",
];

export const CytoscapeGraph: React.FC<CytoscapeGraphProps> = ({
  nodes,
  edges,
  highlightedPathNodeKeys = [],
  highlightedPathEdgeIds = [],
  cutEdgeIds = [],
  edgeBlastRadius = {},
  activeOverlayTitle,
  activeCutTitle,
  onClearOverlay,
  onSelectNode,
  onSelectEdge,
  onSimulateEdgeCut,
  canvasHeight,
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);
  const headingId = useId();
  const tableRegionId = useId();
  const searchInputId = useId();
  const factSelectId = useId();
  const relSelectId = useId();
  const layoutSelectId = useId();

  const [factFilter, setFactFilter] = useState<string>("ALL");
  const [relFilter, setRelFilter] = useState<string>("ALL");
  const [searchTerm, setSearchTerm] = useState<string>("");
  const [layoutMode, setLayoutMode] = useState<"breadthfirst" | "cose">("breadthfirst");
  const [renderLimit, setRenderLimit] = useState<number>(150);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);
  const [showTableView, setShowTableView] = useState<boolean>(false);

  const hasActiveFocus =
    highlightedPathNodeKeys.length > 0 ||
    highlightedPathEdgeIds.length > 0 ||
    cutEdgeIds.length > 0;

  const filteredData = useMemo(() => {
    const query = searchTerm.trim().toLowerCase();
    const keptEdges = edges.filter((e) => {
      if (factFilter !== "ALL" && e.fact_kind !== factFilter) return false;
      if (relFilter !== "ALL" && e.relation_type !== relFilter) return false;
      return true;
    });

    const priorityNodeKeys = new Set<string>(highlightedPathNodeKeys);
    const cutSet = new Set<string>(cutEdgeIds);
    const hlEdgeSet = new Set<string>(highlightedPathEdgeIds);
    for (const e of keptEdges) {
      if (cutSet.has(e.edge_id) || hlEdgeSet.has(e.edge_id)) {
        priorityNodeKeys.add(e.source);
        priorityNodeKeys.add(e.target);
      }
    }

    const nodePool = nodes.filter((n) => {
      if (!query) return true;
      return (
        n.label.toLowerCase().includes(query) ||
        n.node_kind.toLowerCase().includes(query) ||
        n.key.toLowerCase().includes(query)
      );
    });

    const orderedPool =
      priorityNodeKeys.size > 0
        ? [
            ...nodePool.filter((n) => priorityNodeKeys.has(n.key)),
            ...nodePool.filter((n) => !priorityNodeKeys.has(n.key)),
          ]
        : nodePool;

    const cappedNodes = orderedPool.slice(0, renderLimit);
    const cappedKeys = new Set(cappedNodes.map((n) => n.key));
    const visibleEdges = keptEdges.filter(
      (e) => cappedKeys.has(e.source) && cappedKeys.has(e.target)
    );

    return {
      nodes: cappedNodes,
      edges: visibleEdges,
      totalNodes: nodes.length,
      totalEdges: edges.length,
      truncated: orderedPool.length > renderLimit,
    };
  }, [
    cutEdgeIds,
    edges,
    factFilter,
    highlightedPathEdgeIds,
    highlightedPathNodeKeys,
    nodes,
    relFilter,
    renderLimit,
    searchTerm,
  ]);

  useEffect(() => {
    if (!containerRef.current) return;

    const cutEdgesSet = new Set(cutEdgeIds);
    const highlightEdgesSet = new Set(highlightedPathEdgeIds);
    const highlightNodesSet = new Set(highlightedPathNodeKeys);
    for (const e of filteredData.edges) {
      if (cutEdgesSet.has(e.edge_id) || highlightEdgesSet.has(e.edge_id)) {
        highlightNodesSet.add(e.source);
        highlightNodesSet.add(e.target);
      }
    }

    const elements: ElementDefinition[] = [
      ...filteredData.nodes.map((n) => ({
        data: {
          id: n.key,
          label:
            (n.is_external_entry ? "[ENTRY] " : n.is_crown_jewel ? "[CROWN] " : "") + n.label,
          node_kind: n.node_kind,
          criticality: n.criticality,
          highlighted: highlightNodesSet.has(n.key) ? "yes" : "no",
          dimmed: hasActiveFocus && !highlightNodesSet.has(n.key) ? "yes" : "no",
          raw: n,
        },
      })),
      ...filteredData.edges.map((e) => {
        const isCut = cutEdgesSet.has(e.edge_id);
        const isHl = highlightEdgesSet.has(e.edge_id);
        const blast = edgeBlastRadius[e.edge_id];
        const prefix = isCut ? "[CUT] " : blast?.is_single_point_chokepoint ? "[CHOKE] " : "";
        return {
          data: {
            id: e.edge_id,
            source: e.source,
            target: e.target,
            label: `${prefix}${e.relation_type} (${Math.round(e.confidence * 100)}%)`,
            fact_kind: e.fact_kind,
            relation_type: e.relation_type,
            highlighted: isHl ? "yes" : "no",
            cut: isCut ? "yes" : "no",
            chokepoint: blast?.is_single_point_chokepoint ? "yes" : "no",
            dimmed: hasActiveFocus && !isHl && !isCut ? "yes" : "no",
            raw: e,
          },
        };
      }),
    ];

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "text-valign": "bottom",
            "text-margin-y": 6,
            "font-size": "11px",
            "font-weight": "bold",
            color: "#0f172a",
            "text-background-color": "#ffffff",
            "text-background-opacity": 0.9,
            "text-background-padding": "2px",
            width: 34,
            height: 34,
            "border-width": 2,
            "border-color": "#334155",
            "background-color": "#e2e8f0",
          },
        },
        {
          selector: 'node[node_kind = "asset"]',
          style: {
            shape: "round-rectangle",
            "background-color": "#dbeafe",
            "border-color": "#1d4ed8",
          },
        },
        {
          selector: 'node[node_kind = "identity"]',
          style: {
            shape: "ellipse",
            "background-color": "#ede9fe",
            "border-color": "#6d28d9",
          },
        },
        {
          selector: 'node[node_kind = "group"]',
          style: {
            shape: "hexagon",
            "background-color": "#fef3c7",
            "border-color": "#b45309",
          },
        },
        {
          selector: 'node[node_kind = "service"]',
          style: {
            shape: "diamond",
            "background-color": "#dcfce7",
            "border-color": "#15803d",
            width: 26,
            height: 26,
          },
        },
        {
          selector: 'node[criticality = "critical"]',
          style: {
            "border-width": 4,
            "border-color": "#b91c1c",
          },
        },
        {
          selector: 'node[dimmed = "yes"]',
          style: {
            opacity: 0.28,
          },
        },
        {
          selector: 'node[highlighted = "yes"]',
          style: {
            "background-color": "#fecaca",
            "border-color": "#991b1b",
            "border-width": 4,
            opacity: 1,
          },
        },
        {
          selector: "edge",
          style: {
            width: 2,
            "line-color": "#475569",
            "target-arrow-color": "#475569",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": "9px",
            color: "#1e293b",
            "text-rotation": "autorotate",
            "text-background-color": "#ffffff",
            "text-background-opacity": 0.9,
            "text-background-padding": "2px",
          },
        },
        {
          selector: 'edge[fact_kind = "inferred_relationship"]',
          style: {
            "line-style": "dashed",
            "line-color": "#b45309",
            "target-arrow-color": "#b45309",
          },
        },
        {
          selector: 'edge[fact_kind = "analyst_assertion"]',
          style: {
            "line-style": "dotted",
            "line-color": "#1d4ed8",
            "target-arrow-color": "#1d4ed8",
          },
        },
        {
          selector: 'edge[dimmed = "yes"]',
          style: {
            opacity: 0.2,
          },
        },
        {
          selector: 'edge[chokepoint = "yes"]',
          style: {
            width: 3,
          },
        },
        {
          selector: 'edge[highlighted = "yes"]',
          style: {
            width: 4,
            "line-color": "#b91c1c",
            "target-arrow-color": "#b91c1c",
            opacity: 1,
          },
        },
        {
          selector: 'edge[cut = "yes"]',
          style: {
            width: 5,
            "line-style": "dashed",
            "line-color": "#d97706",
            "target-arrow-color": "#d97706",
            opacity: 1,
          },
        },
      ],
      layout: {
        name: layoutMode,
        directed: true,
        padding: 28,
        animate: false,
      },
    });

    cy.on("tap", "node", (evt) => {
      const raw = evt.target.data("raw") as GraphNode;
      setSelectedNode(raw);
      setSelectedEdge(null);
      onSelectNode?.(raw);
    });

    cy.on("tap", "edge", (evt) => {
      const raw = evt.target.data("raw") as GraphEdge;
      setSelectedEdge(raw);
      setSelectedNode(null);
      onSelectEdge?.(raw);
    });

    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [
    cutEdgeIds,
    edgeBlastRadius,
    filteredData,
    hasActiveFocus,
    highlightedPathEdgeIds,
    highlightedPathNodeKeys,
    layoutMode,
    onSelectEdge,
    onSelectNode,
  ]);

  const handleZoomFit = () => {
    cyRef.current?.fit(undefined, 28);
  };

  const handleZoomIn = () => {
    const cy = cyRef.current;
    if (cy) cy.zoom(cy.zoom() * 1.2);
  };

  const handleZoomOut = () => {
    const cy = cyRef.current;
    if (cy) cy.zoom(cy.zoom() * 0.8);
  };

  return (
    <section aria-labelledby={headingId}>
      <h3 id={headingId} className="visually-hidden">
        Interactive Attack Graph Explorer
      </h3>

      <div
        className="card"
        style={{
          marginBlockEnd: "0.75rem",
          display: "flex",
          flexWrap: "wrap",
          gap: "0.75rem",
          alignItems: "end",
        }}
      >
        <div className="field" style={{ minWidth: "12rem", flex: "1 1 12rem" }}>
          <label htmlFor={searchInputId}>Filter Nodes</label>
          <input
            id={searchInputId}
            type="search"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="web-dmz, db-crown, svc..."
            autoCorrect="off"
            autoCapitalize="none"
            spellCheck={false}
          />
        </div>

        <div className="field" style={{ minWidth: "11rem" }}>
          <label htmlFor={factSelectId}>Fact Provenance</label>
          <select
            id={factSelectId}
            value={factFilter}
            onChange={(e) => setFactFilter(e.target.value)}
          >
            <option value="ALL">All Provenance Kinds</option>
            <option value="observed_fact">Observed Facts Only</option>
            <option value="inferred_relationship">Inferred Edges Only</option>
            <option value="analyst_assertion">Analyst Assertions Only</option>
          </select>
        </div>

        <div className="field" style={{ minWidth: "12rem" }}>
          <label htmlFor={relSelectId}>Relationship Type</label>
          <select
            id={relSelectId}
            value={relFilter}
            onChange={(e) => setRelFilter(e.target.value)}
          >
            {RELATION_TYPES.map((rt) => (
              <option key={rt} value={rt}>
                {rt === "ALL" ? "All Edge Types" : rt}
              </option>
            ))}
          </select>
        </div>

        <div className="field" style={{ minWidth: "10rem" }}>
          <label htmlFor={layoutSelectId}>Layout</label>
          <select
            id={layoutSelectId}
            value={layoutMode}
            onChange={(e) => setLayoutMode(e.target.value as "breadthfirst" | "cose")}
          >
            <option value="breadthfirst">Breadthfirst Tree</option>
            <option value="cose">Force-Directed (COSE)</option>
          </select>
        </div>

        <div className="btn-row">
          <button type="button" className="btn btn-secondary btn-sm" onClick={handleZoomFit}>
            Zoom to Fit
          </button>
          <button type="button" className="btn btn-secondary btn-sm" onClick={handleZoomIn}>
            + Zoom In
          </button>
          <button type="button" className="btn btn-secondary btn-sm" onClick={handleZoomOut}>
            − Zoom Out
          </button>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            aria-expanded={showTableView}
            onClick={() => setShowTableView((s) => !s)}
          >
            {showTableView ? "Hide Table View" : "Accessible Edge Table"}
          </button>
        </div>
      </div>

      {filteredData.truncated && (
        <div className="alert alert-warning" role="status">
          <strong>
            Progressive rendering active: displaying {filteredData.nodes.length} of{" "}
            {filteredData.totalNodes} nodes to preserve browser responsiveness.
          </strong>
          <div className="btn-row" style={{ marginTop: "0.35rem" }}>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => setRenderLimit((n) => n + 250)}
            >
              Load +250 Nodes
            </button>
          </div>
        </div>
      )}

      {(activeOverlayTitle || activeCutTitle) && (
        <div className="graph-toolbar-banner" role="status">
          <div>
            {activeOverlayTitle && (
              <div>
                <strong>Active Path Focus:</strong> {activeOverlayTitle}
              </div>
            )}
            {activeCutTitle && (
              <div>
                <strong>Cut-Set Overlay [CUT]:</strong> {activeCutTitle}
              </div>
            )}
          </div>
          {onClearOverlay && (
            <button type="button" className="btn btn-secondary btn-sm" onClick={onClearOverlay}>
              Reset Graph Focus
            </button>
          )}
        </div>
      )}

      <div className="split-drawer-layout">
        <div className="graph-stage">
          <div
            ref={containerRef}
            className="graph-canvas"
            style={canvasHeight ? { height: `${canvasHeight}px` } : undefined}
            aria-label={`Attack graph canvas displaying ${filteredData.nodes.length} nodes and ${filteredData.edges.length} edges`}
          />
          <div className="graph-minimap" aria-hidden="true">
            <strong>Graph Overview</strong>
            <div>Nodes: {filteredData.nodes.length}</div>
            <div>Edges: {filteredData.edges.length}</div>
            <div>Layout: {layoutMode}</div>
          </div>
          <div className="graph-legend">
            <span>▢ Asset</span>
            <span>◯ Identity</span>
            <span>⬡ Group</span>
            <span>◇ Service</span>
            <span>━━ Observed</span>
            <span>┈ Inferred</span>
            <span>■ Crimson = Active Path</span>
            <span>┈ [CUT] Amber = Remediation Cut</span>
          </div>
        </div>

        <aside className="card" aria-label="Selected Graph Element Inspector">
          <h3 className="card-title">Selection Inspector</h3>
          {!selectedNode && !selectedEdge && (
            <p style={{ color: "var(--text-secondary)", margin: 0 }}>
              Click any node or relationship edge in the canvas (or inspect rows in the Accessible
              Edge Table) to view blast radius, counterfactual impact, provenance, and 1-click
              remediation controls.
            </p>
          )}

          {selectedNode && (
            <div className="form-stack">
              <div>
                <strong>{selectedNode.label}</strong>
                <div className="mono">{selectedNode.key}</div>
              </div>
              <div className="btn-row">
                <CriticalityBadge level={selectedNode.criticality} />
                <span className="badge badge-neutral">Kind: {selectedNode.node_kind}</span>
                <span className="badge badge-neutral">Env: {selectedNode.environment}</span>
              </div>
              {selectedNode.is_external_entry && (
                <span className="badge badge-info">→ External Entry Point</span>
              )}
              {selectedNode.is_crown_jewel && (
                <span className="badge badge-critical">★ Crown Jewel Target</span>
              )}
              <div>Open CVE observations: {selectedNode.open_cve_count}</div>
              <pre
                className="mono"
                style={{
                  background: "var(--bg-subtle)",
                  padding: "0.65rem",
                  borderRadius: "0.375rem",
                  overflowX: "auto",
                  margin: 0,
                }}
              >
                {JSON.stringify(selectedNode.metadata, null, 2)}
              </pre>
            </div>
          )}

          {selectedEdge && (() => {
            const blast = edgeBlastRadius[selectedEdge.edge_id];
            return (
              <div className="form-stack">
                <div>
                  <strong>{selectedEdge.relation_type}</strong>
                  <div className="mono">
                    {selectedEdge.source} → {selectedEdge.target}
                  </div>
                </div>
                <div className="btn-row">
                  <ProvenanceBadge factKind={selectedEdge.fact_kind} />
                  <span className="badge badge-info">
                    Confidence: {Math.round(selectedEdge.confidence * 100)}%
                  </span>
                </div>
                {blast && (
                  <div
                    style={{
                      background: blast.is_single_point_chokepoint ? "#fef2f2" : "var(--bg-subtle)",
                      border: `1px solid ${blast.is_single_point_chokepoint ? "#fca5a5" : "var(--border-subtle)"}`,
                      borderRadius: "0.4rem",
                      padding: "0.7rem",
                      fontSize: "0.86rem",
                    }}
                  >
                    <div style={{ marginBlockEnd: "0.35rem" }}>
                      {blast.is_single_point_chokepoint ? (
                        <span className="badge badge-critical">
                          ★ Single-Point Chokepoint (100% Elimination)
                        </span>
                      ) : (
                        <span className="badge badge-medium">
                          {blast.residual_paths_if_cut} Bypass Path(s) Remain If Cut
                        </span>
                      )}
                    </div>
                    <div>
                      Traverses{" "}
                      <strong>
                        {blast.paths_traversed_count} / {blast.total_paths}
                      </strong>{" "}
                      active paths ({blast.path_coverage_pct}%)
                    </div>
                    <div>
                      Edge Betweenness:{" "}
                      <code className="mono">{blast.betweenness_centrality}</code>
                    </div>
                    {blast.critical_targets_affected.length > 0 && (
                      <div>Targets: {blast.critical_targets_affected.join(", ")}</div>
                    )}
                    {onSimulateEdgeCut && (
                      <div style={{ marginBlockStart: "0.55rem" }}>
                        <button
                          type="button"
                          className="btn btn-primary btn-sm"
                          onClick={() => onSimulateEdgeCut(selectedEdge, blast)}
                        >
                          Simulate Breaking This Edge
                        </button>
                      </div>
                    )}
                  </div>
                )}
                <div>
                  <strong>Evidence Provenance</strong>
                  <pre
                    className="mono"
                    style={{
                      background: "var(--bg-subtle)",
                      padding: "0.65rem",
                      borderRadius: "0.375rem",
                      overflowX: "auto",
                      margin: "0.35rem 0 0",
                    }}
                  >
                    {JSON.stringify(selectedEdge.provenance, null, 2)}
                  </pre>
                </div>
              </div>
            );
          })()}
        </aside>
      </div>

      {showTableView && (
        <div
          className="table-region"
          tabIndex={0}
          role="region"
          aria-labelledby={tableRegionId}
          style={{ marginBlockStart: "1rem" }}
        >
          <table className="data-table">
            <caption id={tableRegionId}>
              Keyboard-Accessible Graph Edges ({filteredData.edges.length} edges)
            </caption>
            <thead>
              <tr>
                <th scope="col">Relation</th>
                <th scope="col">Source Node</th>
                <th scope="col">Target Node</th>
                <th scope="col">Provenance</th>
                <th scope="col">Confidence</th>
                <th scope="col">Inspect</th>
              </tr>
            </thead>
            <tbody>
              {filteredData.edges.map((e) => (
                <tr key={e.edge_id}>
                  <th scope="row" data-label="Relation" className="mono">
                    {e.relation_type}
                  </th>
                  <td data-label="Source Node" className="mono">
                    {e.source}
                  </td>
                  <td data-label="Target Node" className="mono">
                    {e.target}
                  </td>
                  <td data-label="Provenance">
                    <ProvenanceBadge factKind={e.fact_kind} />
                  </td>
                  <td data-label="Confidence">{Math.round(e.confidence * 100)}%</td>
                  <td data-label="Inspect">
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={() => {
                        setSelectedEdge(e);
                        setSelectedNode(null);
                        onSelectEdge?.(e);
                      }}
                    >
                      Inspect Edge
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
};
