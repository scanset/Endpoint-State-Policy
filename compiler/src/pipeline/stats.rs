use std::time::Duration;

/// Pipeline processing statistics
#[derive(Debug, Clone)]
pub struct PipelineStats {
    pub total_files_processed: usize,
    pub successful_parses: usize,
    pub failed_parses: usize,
    pub average_processing_time: Duration,
    pub total_tokens_processed: usize,
    pub total_bytes_processed: usize,
}

impl PipelineStats {
    pub fn success_rate(&self) -> f64 {
        if self.total_files_processed == 0 {
            0.0
        } else {
            self.successful_parses as f64 / self.total_files_processed as f64
        }
    }

    pub fn average_processing_rate(&self) -> f64 {
        if self.average_processing_time.as_secs_f64() > 0.0 {
            self.total_bytes_processed as f64 / self.average_processing_time.as_secs_f64()
        } else {
            0.0
        }
    }
}

/// Get pipeline processing statistics for debugging
pub fn get_pipeline_stats() -> PipelineStats {
    PipelineStats {
        total_files_processed: 0, // Would be tracked in real implementation
        successful_parses: 0,
        failed_parses: 0,
        average_processing_time: Duration::from_secs(0),
        total_tokens_processed: 0,
        total_bytes_processed: 0,
    }
}
