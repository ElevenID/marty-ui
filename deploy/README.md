# Deployment source map

Choose an [installation path](../docs/installation-paths.md) before using a
configuration. Source layout does not establish release admission or production
qualification.

| Area | Location |
| --- | --- |
| Grouped Compose source overlays | [Compose index](compose/README.md) |
| Helm charts | [helm/](helm/) |
| K3s development infrastructure | [k3s/](k3s/) |
| Existing Kubernetes resources | [../k8s/](../k8s/) |
| Deployment catalog, environment selection, and bundle assets | [Deployment configuration](../deploy-config/README.md) |

The first Compose organization batch relocates only local-development overlays.
Existing base, production, self-host, installer, and protected-acceptance paths
remain unchanged. See the [migration audit and next batches](../docs/development/compose-layout-migration.md).
