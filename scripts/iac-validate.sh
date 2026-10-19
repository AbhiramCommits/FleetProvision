#!/usr/bin/env bash
# Validate infrastructure-as-code.
#
# Usage: scripts/iac-validate.sh [all|terraform|packer|ansible]
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.tools:$PWD/.venv-tools/bin:$PATH"
export TF_IN_AUTOMATION=1

MODE="${1:-all}"
LOG="results/iac-${MODE}.txt"
if [[ "$MODE" == "all" ]]; then
  LOG="results/iac-validate.txt"
fi
mkdir -p results out
: >"$LOG"

run() {
  echo "\$ $*" | tee -a "$LOG"
  "$@" 2>&1 | tee -a "$LOG"
}

log() {
  echo "$*" | tee -a "$LOG"
}

if [[ -x .venv-tools/bin/python ]]; then
  PY=.venv-tools/bin/python
else
  PY=python3
fi

log "== YAML parse: .gitlab-ci.yml =="
"$PY" -c "import yaml;yaml.safe_load(open('.gitlab-ci.yml'));print('gitlab-ci.yml: valid YAML')" | tee -a "$LOG"

validate_terraform() {
  log "== terraform fmt -check -recursive =="
  run terraform fmt -check -recursive terraform

  local modules=(terraform/modules/aws_vpc terraform/modules/aws_node terraform/modules/onprem_rack)
  local envs=(terraform/envs/dev terraform/envs/onprem)
  local validated=0
  local dir

  for dir in "${modules[@]}"; do
    log "== terraform validate: $dir =="
    (cd "$dir" && terraform init -backend=false -input=false -no-color >/dev/null)
    run terraform -chdir="$dir" validate -no-color
    validated=$((validated + 1))
  done
  for dir in "${envs[@]}"; do
    log "== terraform validate: $dir =="
    (cd "$dir" && terraform init -backend=false -input=false -no-color >/dev/null)
    run terraform -chdir="$dir" validate -no-color
    validated=$((validated + 1))
  done

  cat >out/dev.tfvars <<'EOF'
# Offline plan inputs. Dummy credentials are intentional.
aws_region      = "us-east-1"
aws_access_key  = "AKIAIOSFODNN7EXAMPLE"
aws_secret_key  = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
node_ami        = "ami-0123456789abcdef0"
node_count      = 2
bastion_cidr    = "203.0.113.0/24"
bootstrap_token = "offline-plan-token"
trust_bundle    = "-----BEGIN CERTIFICATE-----\nOFFLINE-PLAN-ONLY\n-----END CERTIFICATE-----\n"
EOF

  log "== terraform plan: envs/dev =="
  (cd terraform/envs/dev && terraform plan -input=false -refresh=false -no-color \
    -var-file="../../../out/dev.tfvars" -out="../../../out/dev.tfplan") 2>&1 | tee -a "$LOG"

  terraform -chdir=terraform/envs/dev show -json ../../../out/dev.tfplan >out/dev-plan.json
  "$PY" - <<'PYEOF' | tee -a "$LOG"
import json
data = json.load(open("out/dev-plan.json"))
resources = 0
modules = []

def walk(module):
    global resources
    resources += len(module.get("resources", []))
    for child in module.get("child_modules", []):
        modules.append(child.get("address"))
        walk(child)

walk(data["planned_values"]["root_module"])
summary = {
    "resources_planned": resources,
    "module_addresses": sorted(modules),
    "terraform_version": data.get("terraform_version"),
}
json.dump(summary, open("results/iac-plan-counts.json", "w"), indent=2)
print(f"planned resources: {resources}")
print(f"child modules: {', '.join(sorted(modules))}")
PYEOF
  "$PY" - "$validated" <<'PYEOF'
import json, sys
path = "results/iac-plan-counts.json"
data = json.load(open(path))
data["modules_validated"] = int(sys.argv[1])
json.dump(data, open(path, "w"), indent=2)
print(f"modules/environments validated: {data['modules_validated']}")
PYEOF
  log "modules/environments validated: $validated"
}

validate_packer() {
  if ! command -v packer >/dev/null 2>&1; then
    log "packer is not installed"
    exit 1
  fi
  if [[ ! -x target/release/fleet-agent && "${SKIP_AGENT_BUILD:-0}" != "1" ]]; then
    log "== building release fleet-agent for Packer validation =="
    run cargo build --release -p fleetd --bin fleet-agent
  fi
  local dir
  for dir in packer/ubuntu packer/fedora; do
    log "== packer init + validate: $dir =="
    (cd "$dir" && packer init . 2>&1 | tee -a "../../$LOG" && packer validate . 2>&1 | tee -a "../../$LOG")
  done
}

validate_ansible() {
  if ! command -v ansible-lint >/dev/null 2>&1; then
    log "ansible-lint is not installed"
    exit 1
  fi
  log "== ansible-lint =="
  (cd ansible && ansible-lint . 2>&1 | tee -a "../$LOG")
}

case "$MODE" in
  all)
    validate_terraform
    validate_packer
    validate_ansible
    ;;
  terraform) validate_terraform ;;
  packer) validate_packer ;;
  ansible) validate_ansible ;;
  *)
    echo "unknown mode $MODE (expected all, terraform, packer, or ansible)" >&2
    exit 2
    ;;
esac

log "iac validation complete ($MODE)"
