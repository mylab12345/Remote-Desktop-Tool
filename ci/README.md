# Continuous integration

`ci/ci.yml` is the CI definition.  It is kept here rather than in
`.github/workflows/` because the automation account used to maintain this
repository is not granted the `workflows` permission, and GitHub refuses pushes
that create or update workflow files without it.

To activate it, a maintainer with that permission copies it into place:

```bash
mkdir -p .github/workflows
cp ci/ci.yml .github/workflows/ci.yml
git add .github && git commit -m "Enable CI" && git push
```

The pipeline runs, on Ubuntu 24.04 and Windows 2022:

1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace --locked`
4. `cargo build --workspace --release --locked`

plus a Linux job that type checks the Windows-only code paths with
`cargo check --target x86_64-pc-windows-msvc`.
