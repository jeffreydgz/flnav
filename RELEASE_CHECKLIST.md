# Release Checklist

Use this checklist for each `flnav` release. Do not delete or overwrite old
GitHub releases; increment the version number and publish a new release.

## Version Bump

- [ ] Choose the next version number.
- [ ] Update `AC_INIT` in `configure.ac`.
- [ ] Update `project(... VERSION ...)` in `CMakeLists.txt`.
- [ ] Confirm `src/flnav -V` reports the expected version after rebuild.

## Build And Test

- [ ] Install rebuild dependencies from the README.
- [ ] Run `export PATH="$HOME/.cargo/bin:$PATH"` when `cxxbridge` was installed
      through cargo.
- [ ] Run `./autogen.sh`.
- [ ] Run `./configure`.
- [ ] Run `make -j"$(nproc)"`.
- [ ] Run `make -C test check TESTS=test_forensics.sh`.
- [ ] Run a smoke test with `src/flnav --ioc <ioc-file> <log-file>`.
- [ ] Review generated docs or schemas and commit only intentional changes.
- [ ] Run `tools/package-release.sh X.Y.Z` if creating artifacts locally.
- [ ] Verify `release-artifacts/flnav-X.Y.Z-SHA256SUMS.txt` with
      `sha256sum -c`.

## GitHub Release

- [ ] Create a signed-off release commit or tag for `vX.Y.Z`.
- [ ] Push the release commit and tag to `https://github.com/jeffreydgz/flnav`.
- [ ] Let the `CI` workflow pass on GitHub for the release commit.
- [ ] Preferred path: run the manual `Release` workflow with the incremented
      version number.
- [ ] Local fallback: load the GitHub token from `/home/dev/.env` if using
      `gh`; never commit the token or print it in logs.
- [ ] Create a new GitHub release for the incremented version only.
- [ ] Attach `flnav-X.Y.Z-source.tar.gz`,
      `flnav-X.Y.Z-linux-<arch>.tar.gz`, and
      `flnav-X.Y.Z-SHA256SUMS.txt`.
- [ ] Leave all older GitHub releases in place.
