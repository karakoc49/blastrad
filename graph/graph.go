package graph

import "fmt"

// Graph holds all nodes and the edges between them.
//
// Uses an adjacency list representation:
// Each node ID → list of edges leaving that node
//
// Why adjacency list?
// - Well suited for path finding (DFS/BFS)
// - Answers "where can I go from this node?" in O(1)
// - Memory-efficient for sparse graphs (pipelines are sparse)
type Graph struct {
	// nodes: ID → Node. Stores all nodes.
	nodes map[string]*Node

	// edges: from_ID → []Edge. Adjacency list.
	// Quickly answers "which nodes can you reach from node A?"
	edges map[string][]Edge
}

// New creates an empty graph.
func New() *Graph {
	return &Graph{
		nodes: make(map[string]*Node),
		edges: make(map[string][]Edge),
	}
}

// AddNode adds a new node to the graph.
// Overwrites if a node with the same ID already exists.
func (g *Graph) AddNode(node *Node) {
	g.nodes[node.ID] = node
}

// AddEdge adds a directed edge between two nodes.
// Both From and To nodes must already exist in the graph.
func (g *Graph) AddEdge(from, to string, edgeType EdgeType) error {
	if _, ok := g.nodes[from]; !ok {
		return fmt.Errorf("node '%s' not in graph", from)
	}
	if _, ok := g.nodes[to]; !ok {
		return fmt.Errorf("node '%s' not in graph", to)
	}

	edge := Edge{From: from, To: to, Type: edgeType}
	g.edges[from] = append(g.edges[from], edge)
	return nil
}

// GetNode returns a node by ID.
func (g *Graph) GetNode(id string) (*Node, bool) {
	node, ok := g.nodes[id]
	return node, ok
}

// Neighbors returns the list of nodes directly reachable from a node.
// Used by DFS/BFS algorithms.
func (g *Graph) Neighbors(nodeID string) []*Node {
	var result []*Node
	for _, edge := range g.edges[nodeID] {
		if node, ok := g.nodes[edge.To]; ok {
			result = append(result, node)
		}
	}
	return result
}

// EdgesFrom returns all edges leaving a node.
// Used to filter edges by type.
func (g *Graph) EdgesFrom(nodeID string) []Edge {
	return g.edges[nodeID]
}

// AllNodes returns all nodes in the graph.
func (g *Graph) AllNodes() []*Node {
	result := make([]*Node, 0, len(g.nodes))
	for _, node := range g.nodes {
		result = append(result, node)
	}
	return result
}

// NodeCount returns the total number of nodes in the graph.
func (g *Graph) NodeCount() int {
	return len(g.nodes)
}

// EdgeCount returns the total number of edges in the graph.
func (g *Graph) EdgeCount() int {
	total := 0
	for _, edges := range g.edges {
		total += len(edges)
	}
	return total
}
