use crate::symbols::SymbolDiscoveryResult;
use common::ast::nodes::EspFile;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct PipelineOutput {
    pub ast_tree: EspFile,
    pub symbols: SymbolDiscoveryResult,
}

impl PipelineOutput {
    pub fn new(ast_tree: EspFile, symbols: SymbolDiscoveryResult) -> Self {
        Self { ast_tree, symbols }
    }
}
