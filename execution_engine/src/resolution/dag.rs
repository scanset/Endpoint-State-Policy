//! Dependency Graph (DAG) implementation for ICS resolution engine
//! Handles topological sorting and cycle detection for symbol resolution

use crate::resolution::error::ResolutionError;
use crate::types::criterion::CtnNodeId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// Types of symbols that can be resolved in the DAG
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)] // Already has Clone
pub enum SymbolType {
    Variable,
    GlobalState,
    GlobalObject,
    SetOperation,
    RuntimeOperation,
    LocalState,
    LocalObject,
}

impl SymbolType {
    /// Convert from string representation (for JSON parsing)
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "Variable" => Some(Self::Variable),
            "GlobalState" => Some(Self::GlobalState),
            "GlobalObject" => Some(Self::GlobalObject),
            "SetOperation" => Some(Self::SetOperation),
            "RuntimeOperation" => Some(Self::RuntimeOperation),
            "LocalState" => Some(Self::LocalState),
            "LocalObject" => Some(Self::LocalObject),
            _ => None,
        }
    }

    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Variable => "Variable",
            Self::GlobalState => "GlobalState",
            Self::GlobalObject => "GlobalObject",
            Self::SetOperation => "SetOperation",
            Self::RuntimeOperation => "RuntimeOperation",
            Self::LocalState => "LocalState",
            Self::LocalObject => "LocalObject",
        }
    }

    /// Check if this symbol type is global scope
    pub fn is_global(&self) -> bool {
        matches!(
            self,
            Self::Variable
                | Self::GlobalState
                | Self::GlobalObject
                | Self::SetOperation
                | Self::RuntimeOperation
        )
    }

    /// Check if this symbol type is local (CTN) scope
    pub fn is_local(&self) -> bool {
        matches!(self, Self::LocalState | Self::LocalObject)
    }
}

/// Node in the dependency graph representing a resolvable symbol
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)] // Added Clone
pub struct SymbolNode {
    pub symbol_id: String,
    pub symbol_type: SymbolType,
    pub ctn_context: Option<CtnNodeId>,
    pub dependencies: Vec<String>,
    pub dependents: Vec<String>,
}

impl SymbolNode {
    /// Create new symbol node
    pub fn new(symbol_id: String, symbol_type: SymbolType) -> Self {
        Self {
            symbol_id,
            symbol_type,
            ctn_context: None,
            dependencies: Vec::new(),
            dependents: Vec::new(),
        }
    }

    /// Create new local symbol node with CTN context
    pub fn new_local(symbol_id: String, symbol_type: SymbolType, ctn_id: CtnNodeId) -> Self {
        Self {
            symbol_id,
            symbol_type,
            ctn_context: Some(ctn_id),
            dependencies: Vec::new(),
            dependents: Vec::new(),
        }
    }

    /// Add dependency to this node
    pub fn add_dependency(&mut self, dependency: String) {
        if !self.dependencies.contains(&dependency) {
            self.dependencies.push(dependency);
        }
    }

    /// Add dependent to this node
    pub fn add_dependent(&mut self, dependent: String) {
        if !self.dependents.contains(&dependent) {
            self.dependents.push(dependent);
        }
    }

    /// Check if node has dependencies
    pub fn has_dependencies(&self) -> bool {
        !self.dependencies.is_empty()
    }

    /// Get dependency count
    pub fn dependency_count(&self) -> usize {
        self.dependencies.len()
    }
}

/// Dependency graph for symbol resolution ordering
#[derive(Debug, Clone)]
pub struct DependencyGraph {
    pub nodes: HashMap<String, SymbolNode>,
    pub edges: HashMap<String, Vec<String>>, // symbol -> its dependencies
    pub reverse_edges: HashMap<String, Vec<String>>, // symbol -> symbols that depend on it
    pub global_symbols: HashSet<String>,
    pub local_symbols: HashMap<CtnNodeId, HashSet<String>>,
}

impl DependencyGraph {
    /// Create new empty dependency graph
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashMap::new(),
            reverse_edges: HashMap::new(),
            global_symbols: HashSet::new(),
            local_symbols: HashMap::new(),
        }
    }

    /// Add node to the dependency graph
    pub fn add_node(
        &mut self,
        symbol_id: String,
        symbol_type: SymbolType,
    ) -> Result<(), ResolutionError> {
        if self.nodes.contains_key(&symbol_id) {
            return Ok(());
        }

        let node = SymbolNode::new(symbol_id.clone(), symbol_type);

        // Track global vs local symbols
        if symbol_type.is_global() {
            self.global_symbols.insert(symbol_id.clone());
        }

        // Initialize edge lists
        self.edges.insert(symbol_id.clone(), Vec::new());
        self.reverse_edges.insert(symbol_id.clone(), Vec::new());

        // Store the node
        self.nodes.insert(symbol_id.clone(), node);

        Ok(())
    }

    /// Add local node with CTN context
    pub fn add_local_node(
        &mut self,
        symbol_id: String,
        symbol_type: SymbolType,
        ctn_id: CtnNodeId,
    ) -> Result<(), ResolutionError> {
        if self.nodes.contains_key(&symbol_id) {
            return Err(ResolutionError::LocalSymbolConflict {
                symbol: symbol_id,
                ctn_id,
            });
        }

        let node = SymbolNode::new_local(symbol_id.clone(), symbol_type, ctn_id);

        // Track local symbols by CTN
        self.local_symbols
            .entry(ctn_id)
            .or_default()
            .insert(symbol_id.clone());

        // Initialize edge lists
        self.edges.insert(symbol_id.clone(), Vec::new());
        self.reverse_edges.insert(symbol_id.clone(), Vec::new());

        // Store the node
        self.nodes.insert(symbol_id.clone(), node);

        Ok(())
    }

    /// Add dependency edge between two symbols
    /// `from` depends on `to` - meaning `to` must be resolved before `from`
    pub fn add_dependency(&mut self, from: &str, to: &str) -> Result<(), ResolutionError> {
        // Validate both symbols exist
        if !self.nodes.contains_key(from) {
            return Err(ResolutionError::DependencyGraphCorrupted {
                details: format!(
                    "Dependent symbol '{}' not found when adding dependency on '{}'",
                    from, to
                ),
            });
        }

        if !self.nodes.contains_key(to) {
            return Err(ResolutionError::DependencyGraphCorrupted {
                details: format!(
                    "Dependency symbol '{}' not found when adding dependency from '{}'",
                    to, from
                ),
            });
        }

        // Add edge: from depends on to (to must resolve first)
        self.edges
            .entry(from.to_string())
            .or_default()
            .push(to.to_string());

        // Add reverse edge: to is depended on by from
        self.reverse_edges
            .entry(to.to_string())
            .or_default()
            .push(from.to_string());

        // Update node dependency lists
        if let Some(node) = self.nodes.get_mut(from) {
            node.add_dependency(to.to_string());
        }
        if let Some(node) = self.nodes.get_mut(to) {
            node.add_dependent(from.to_string());
        }

        Ok(())
    }

    /// Get dependencies for a symbol
    pub fn get_dependencies(&self, symbol: &str) -> Vec<String> {
        self.edges.get(symbol).cloned().unwrap_or_default()
    }

    /// Get dependents for a symbol
    pub fn get_dependents(&self, symbol: &str) -> Vec<String> {
        self.reverse_edges.get(symbol).cloned().unwrap_or_default()
    }

    /// Perform topological sort to get resolution order
    pub fn topological_sort(&self) -> Result<Vec<String>, ResolutionError> {
        // Detect cycles first
        if let Some(cycle) = self.detect_cycle() {
            return Err(ResolutionError::CircularDependency { cycle });
        }

        // Kahn's algorithm for topological sorting
        let mut in_degree: HashMap<String, usize> = HashMap::new();
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        // Initialize in-degrees
        for node_id in self.nodes.keys() {
            let degree = self.get_dependencies(node_id).len();
            in_degree.insert(node_id.clone(), degree);

            if degree == 0 {
                queue.push_back(node_id.clone());
            }
        }

        // Process nodes with no remaining dependencies
        while let Some(current) = queue.pop_front() {
            result.push(current.clone());

            // Update in-degrees for dependents
            for dependent in self.get_dependents(&current) {
                if let Some(degree) = in_degree.get_mut(&dependent) {
                    *degree -= 1;
                    if *degree == 0 {
                        queue.push_back(dependent.clone());
                    }
                }
            }
        }

        // Verify all nodes were processed
        if result.len() != self.nodes.len() {
            let unprocessed: Vec<String> = self
                .nodes
                .keys()
                .filter(|k| !result.contains(k))
                .cloned()
                .collect();

            return Err(ResolutionError::DependencyGraphCorrupted {
                details: format!(
                    "Topological sort incomplete: {} unprocessed nodes",
                    unprocessed.len()
                ),
            });
        }

        Ok(result)
    }

    /// Detect cycles in the dependency graph using DFS
    pub fn detect_cycle(&self) -> Option<Vec<String>> {
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();
        let mut path = Vec::new();

        for node_id in self.nodes.keys() {
            if !visited.contains(node_id) {
                if let Some(cycle) =
                    self.dfs_cycle_detect(node_id, &mut visited, &mut rec_stack, &mut path)
                {
                    return Some(cycle);
                }
            }
        }

        None
    }

    /// DFS-based cycle detection helper
    fn dfs_cycle_detect(
        &self,
        node: &str,
        visited: &mut HashSet<String>,
        rec_stack: &mut HashSet<String>,
        path: &mut Vec<String>,
    ) -> Option<Vec<String>> {
        visited.insert(node.to_string());
        rec_stack.insert(node.to_string());
        path.push(node.to_string());

        // Follow dependencies (outgoing edges)
        for dependency in self.get_dependencies(node) {
            if !visited.contains(&dependency) {
                if let Some(cycle) = self.dfs_cycle_detect(&dependency, visited, rec_stack, path) {
                    return Some(cycle);
                }
            } else if rec_stack.contains(&dependency) {
                // Back edge found - cycle detected
                // Extract cycle from path starting at the back edge target
                if let Some(cycle_start_idx) = path.iter().position(|x| x == &dependency) {
                    let mut cycle = path
                        .get(cycle_start_idx..)
                        .map(|s| s.to_vec())
                        .unwrap_or_default();
                    cycle.push(dependency);
                    return Some(cycle);
                } else {
                    // Fallback: just return the current path as cycle
                    let mut cycle = path.clone();
                    cycle.push(dependency);
                    return Some(cycle);
                }
            }
        }

        rec_stack.remove(node);
        path.pop();
        None
    }

    /// Get graph statistics for monitoring
    pub fn get_stats(&self) -> GraphStats {
        let edge_count: usize = self.edges.values().map(|v| v.len()).sum();
        let max_dependencies = self.edges.values().map(|v| v.len()).max().unwrap_or(0);
        let nodes_with_no_deps = self.edges.values().filter(|v| v.is_empty()).count();

        GraphStats {
            total_nodes: self.nodes.len(),
            total_edges: edge_count,
            global_symbols: self.global_symbols.len(),
            local_symbols: self.local_symbols.values().map(|s| s.len()).sum(),
            max_dependencies,
            nodes_with_no_dependencies: nodes_with_no_deps,
        }
    }

    /// Validate graph integrity
    pub fn validate(&self) -> Result<(), ResolutionError> {
        // Check that all edges reference existing nodes
        for (from, dependencies) in &self.edges {
            if !self.nodes.contains_key(from) {
                return Err(ResolutionError::DependencyGraphCorrupted {
                    details: format!("Edge references non-existent source node: {}", from),
                });
            }

            for to in dependencies {
                if !self.nodes.contains_key(to) {
                    return Err(ResolutionError::DependencyGraphCorrupted {
                        details: format!(
                            "Edge from '{}' references non-existent target node: {}",
                            from, to
                        ),
                    });
                }
            }
        }

        // Check reverse edge consistency
        for (node, dependents) in &self.reverse_edges {
            for dependent in dependents {
                let forward_deps = self.edges.get(dependent);
                if !forward_deps.is_some_and(|deps| deps.contains(node)) {
                    return Err(ResolutionError::DependencyGraphCorrupted {
                        details: format!("Inconsistent reverse edge: {} -> {}", dependent, node),
                    });
                }
            }
        }

        Ok(())
    }

    /// Get symbols that have no dependencies (can be resolved first)
    pub fn get_independent_symbols(&self) -> Vec<String> {
        self.edges
            .iter()
            .filter_map(|(symbol, deps)| {
                if deps.is_empty() {
                    Some(symbol.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get symbols that nothing depends on (leaf nodes)
    pub fn get_leaf_symbols(&self) -> Vec<String> {
        self.reverse_edges
            .iter()
            .filter_map(|(symbol, dependents)| {
                if dependents.is_empty() {
                    Some(symbol.clone())
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Graph statistics for monitoring and debugging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphStats {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub global_symbols: usize,
    pub local_symbols: usize,
    pub max_dependencies: usize,
    pub nodes_with_no_dependencies: usize,
}

impl GraphStats {
    /// Calculate average dependencies per node
    pub fn average_dependencies(&self) -> f64 {
        if self.total_nodes == 0 {
            0.0
        } else {
            self.total_edges as f64 / self.total_nodes as f64
        }
    }

    /// Check if graph is well-balanced (not too many dependencies per node)
    pub fn is_well_balanced(&self) -> bool {
        self.max_dependencies <= 10 && self.average_dependencies() <= 3.0
    }
}

impl Default for DependencyGraph {
    fn default() -> Self {
        Self::new()
    }
}
