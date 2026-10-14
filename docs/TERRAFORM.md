# VXVisor Terraform provider (M8b)

The Terraform provider is a **separate binary**, intentionally *not* part of the
`vdxd` daemon. It talks to the same public REST API (`/api/v1/...`) using an
API key, so anything the provider does, you can also do with `curl`.

This directory documents the provider contract and ships a runnable REST example
(`examples/terraform/`). Building the actual provider plugin uses
`github.com/hashicorp/terraform-plugin-framework` and lives in its own module/repo
(`terraform-provider-vdxclone`) so the daemon stays dependency-light.

## Authentication

Create a key in the UI (Tenancy → API Keys) and export it:

```sh
export VDXCLONE_ENDPOINT="http://172.16.1.67:8766"
export VDXCLONE_TOKEN="vdx_...."
```

## Resources (mapping to the REST API)

| Terraform resource        | REST endpoint                              |
|---------------------------|--------------------------------------------|
| `vdxclone_instance`       | `POST/GET/DELETE /api/v1/sessions`         |
| `vdxclone_instance.start` | `POST /api/v1/sessions/{id}/start`         |
| `vdxclone_template`       | (web) `/templates`                         |
| `vdxclone_network`        | (web) `/networks`                          |
| `vdxclone_snapshot`       | `POST /sessions/{id}/snapshots`            |

## Example (REST, no provider build required)

```sh
# create
curl -s -X POST "$VDXCLONE_ENDPOINT/api/v1/sessions" \
  -H "Authorization: Bearer $VDXCLONE_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"tf-vm","image":"ubuntu-24.04","kind":"server","cpus":2,"memory_mb":2048,"disk_gb":10}'

# start
curl -s -X POST "$VDXCLONE_ENDPOINT/api/v1/sessions/$ID/start" \
  -H "Authorization: Bearer $VDXCLONE_TOKEN"
```

A read-only key (`["read"]` scope) can run `terraform plan`/refresh; a
read-write key is required for `apply`.
