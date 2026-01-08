use super::common::LogicalOp;
use super::criterion::CriterionDeclaration;
use crate::types::execution_context::ExecutableCriterion;
use crate::types::CtnNodeId;
use serde::{Deserialize, Serialize};

/// Tree structure for nested criteria evaluation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CriteriaTree {
    /// Leaf node - actual CTN
    Criterion {
        declaration: CriterionDeclaration,
        node_id: CtnNodeId,
    },

    /// Branch node - CRI block with children
    Block {
        logical_op: LogicalOp,
        negate: bool,
        children: Vec<CriteriaTree>,
    },
}

/// Root container for all criteria
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CriteriaRoot {
    /// Forest of criteria trees (multiple top-level CRI blocks)
    pub trees: Vec<CriteriaTree>,
    /// How to combine top-level trees (default: AND)
    pub root_logical_op: LogicalOp,
}

impl CriteriaTree {
    /// Extract all CTN declarations for dependency analysis
    pub fn extract_all_criteria(&self) -> Vec<&CriterionDeclaration> {
        match self {
            CriteriaTree::Criterion { declaration, .. } => vec![declaration],
            CriteriaTree::Block { children, .. } => children
                .iter()
                .flat_map(|child| child.extract_all_criteria())
                .collect(),
        }
    }

    /// Count total CTNs in tree
    pub fn count_criteria(&self) -> usize {
        match self {
            CriteriaTree::Criterion { .. } => 1,
            CriteriaTree::Block { children, .. } => {
                children.iter().map(|c| c.count_criteria()).sum()
            }
        }
    }

    /// Get maximum nesting depth
    pub fn max_depth(&self) -> usize {
        match self {
            CriteriaTree::Criterion { .. } => 0,
            CriteriaTree::Block { children, .. } => {
                1 + children.iter().map(|c| c.max_depth()).max().unwrap_or(0)
            }
        }
    }
}

impl CriteriaRoot {
    /// Get all CTN declarations across all trees
    pub fn get_all_criteria(&self) -> Vec<&CriterionDeclaration> {
        self.trees
            .iter()
            .flat_map(|tree| tree.extract_all_criteria())
            .collect()
    }

    /// Total count of CTNs
    pub fn total_criteria_count(&self) -> usize {
        self.trees.iter().map(|tree| tree.count_criteria()).sum()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutableCriteriaTree {
    Criterion(ExecutableCriterion),
    Block {
        logical_op: LogicalOp,
        negate: bool,
        children: Vec<ExecutableCriteriaTree>,
    },
}

impl ExecutableCriteriaTree {
    /// Count total CTNs in the tree
    pub fn count_criteria(&self) -> usize {
        match self {
            ExecutableCriteriaTree::Criterion(_) => 1,
            ExecutableCriteriaTree::Block { children, .. } => {
                children.iter().map(|c| c.count_criteria()).sum()
            }
        }
    }
}
