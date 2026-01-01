# Changelog with Security Notes

# 31 DEC 2025 - v.0.1 release

## [0.1.1] - 2026-01-01

### Fixed
- K8sResourceCollector now correctly uses in-cluster authentication when running inside Kubernetes pods. Previously, kubectl would fail to auto-detect ServiceAccount credentials when `KUBERNETES_SERVICE_HOST` was set.
