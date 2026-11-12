# Releasing

Releases are made by the maintainer; nothing is published automatically from the default branch.

1. Move the `[Unreleased]` entries in `CHANGELOG.md` under a new `## [x.y.z] - YYYY-MM-DD` heading
   and commit.
2. Tag the commit and push the tag:

   ```sh
   git tag -s vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```

3. `.github/workflows/release.yml` then
   - refuses a tag on a commit that is not on `main`, runs the checks of CI again (license headers,
     gofmt, `go vet`, golangci-lint, race tests, govulncheck, gitleaks) and refuses a tag without a
     changelog section;
   - builds `linux/amd64` and `linux/arm64` images with `-trimpath`, fixed `-ldflags` and
     `SOURCE_DATE_EPOCH` from the tagged commit, with an SBOM and SLSA provenance (`mode=max`);
   - pushes `bifrost0x/varde:X.Y.Z` and `X.Y` to Docker Hub and GHCR (pre-releases get only the full
     version tag);
   - signs the image digest with cosign (keyless, GitHub OIDC);
   - creates the GitHub release with static binaries, `SHA256SUMS`, its cosign bundle
     (`SHA256SUMS.bundle`) and the changelog section.

Required repository secrets: `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN` (Docker Hub access token with
read/write scope). GHCR and the release use the workflow's `GITHUB_TOKEN`.

Before the first release, once: create the repository `bifrost0x/varde` on Docker Hub. After the
first push to GHCR, set the package `ghcr.io/bifrost0x/varde` to public (Package settings >
Change visibility); GitHub creates new packages as private.

Verify a published image:

```sh
cosign verify docker.io/bifrost0x/varde:X.Y.Z \
  --certificate-identity-regexp 'https://github.com/bifrost0x/varde/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Verify downloaded binaries:

```sh
cosign verify-blob --bundle SHA256SUMS.bundle \
  --certificate-identity-regexp 'https://github.com/bifrost0x/varde/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

There is no `latest` tag; deployments should pin a version and, ideally, the digest.
