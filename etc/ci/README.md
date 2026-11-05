# CI

`ci.yml` is the GitHub Actions workflow. It lives here because the automation token
that pushes to this repo cannot write `.github/workflows/`. To enable it:

```sh
mkdir -p .github/workflows && cp etc/ci/ci.yml .github/workflows/ci.yml
```

Agents: edit `etc/ci/ci.yml` only; never create files under `.github/workflows/`
(the push will be rejected). Run the same checks locally with `just ci` and
`just test-linux`.
