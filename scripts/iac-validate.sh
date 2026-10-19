#!/usr/bin/env bash
# Validate infrastructure-as-code. Implemented incrementally; every stage below
# is a real command, never a mocked result.
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$PWD/.tools:$PATH"

echo "== YAML parse: .gitlab-ci.yml =="
if [[ -x .venv-tools/bin/python ]]; then
  PY=.venv-tools/bin/python
else
  PY=python3
fi
"$PY" -c "import yaml,sys; yaml.safe_load(open('.gitlab-ci.yml')); print('gitlab-ci.yml: valid YAML')"

if command -v terraform >/dev/null 2>&1; then
  echo "== terraform fmt =="
  terraform fmt -check -recursive terraform
else
  echo "terraform not installed; skipping terraform checks" >&2
fi

if command -v packer >/dev/null 2>&1; then
  echo "== packer validate =="
  for t in packer/ubuntu packer/fedora; do
    if compgen -G "$t/*.pkr.hcl" >/dev/null; then
      (cd "$t" && packer init . && packer validate .)
    fi
  done
else
  echo "packer not installed; skipping packer checks" >&2
fi
