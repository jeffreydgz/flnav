#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: tools/package-release.sh [version]

Build release artifacts from the current checkout. If version is omitted, the
version is read from configure.ac.

Environment:
  OUT_DIR                 Output directory. Default: release-artifacts
  FLNAV_BINARY            Binary to package. Default: src/flnav
  FLNAV_RELEASE_PLATFORM  Platform label. Default: linux-$(uname -m)
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${repo_root}"

version="${1:-}"
if [[ -z "${version}" ]]; then
    version="$(
        sed -n 's/^AC_INIT(\[flnav\],\[\([^]]*\)\].*/\1/p' configure.ac \
            | head -n 1
    )"
fi

if [[ ! "${version}" =~ ^[0-9]+[.][0-9]+[.][0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
    echo "error: invalid version '${version}'" >&2
    exit 1
fi

binary="${FLNAV_BINARY:-src/flnav}"
if [[ ! -x "${binary}" ]]; then
    echo "error: '${binary}' is not executable; run make first" >&2
    exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
    echo "warning: working tree is dirty; source archive uses committed HEAD" >&2
fi

out_dir="${OUT_DIR:-release-artifacts}"
platform="${FLNAV_RELEASE_PLATFORM:-linux-$(uname -m)}"
artifact_base="flnav-${version}"
bundle_name="${artifact_base}-${platform}"
source_archive="${out_dir}/${artifact_base}-source.tar.gz"
binary_archive="${out_dir}/${bundle_name}.tar.gz"
checksums="${out_dir}/${artifact_base}-SHA256SUMS.txt"

rm -rf "${out_dir}"
mkdir -p "${out_dir}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

git archive --format=tar --prefix="${artifact_base}/" HEAD \
    | gzip -9 > "${source_archive}"

bundle_dir="${tmp_dir}/${bundle_name}"
mkdir -p "${bundle_dir}/bin" "${bundle_dir}/share/man/man1"

install -m 755 "${binary}" "${bundle_dir}/bin/flnav"
install -m 644 README.md "${bundle_dir}/README.md"
install -m 644 LICENSE "${bundle_dir}/LICENSE"
if [[ -f RELEASE_CHECKLIST.md ]]; then
    install -m 644 RELEASE_CHECKLIST.md "${bundle_dir}/RELEASE_CHECKLIST.md"
fi
if [[ -f flnav.1 ]]; then
    install -m 644 flnav.1 "${bundle_dir}/share/man/man1/flnav.1"
fi

{
    printf 'version=%s\n' "${version}"
    printf 'platform=%s\n' "${platform}"
    printf 'built_from=%s\n' "$(git rev-parse HEAD)"
    "${binary}" -V 2>/dev/null || true
} > "${bundle_dir}/VERSION"

tar -C "${tmp_dir}" -czf "${binary_archive}" "${bundle_name}"

(
    cd "${out_dir}"
    sha256sum "$(basename "${source_archive}")" \
        "$(basename "${binary_archive}")" \
        > "$(basename "${checksums}")"
)

printf 'Created release artifacts:\n'
printf '  %s\n' "${source_archive}"
printf '  %s\n' "${binary_archive}"
printf '  %s\n' "${checksums}"
