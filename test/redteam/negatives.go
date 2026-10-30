package redteam

// negatives are files that look like they contain credentials but do not.
//
// These matter as much as the positives. A scanner that fires on UUIDs,
// git hashes and base64 assets trains developers to push past it, which
// makes it worse than no scanner at all -- so a false positive here is a
// test failure, not a warning.
func negatives(g generator) []Case {
	var cases []Case
	add := func(c Case) { cases = append(cases, c) }

	add(neg("git-sha-in-lockfile", "deps.lock", fmtLines(
		"acme/api "+g.hex(40),
		"acme/lib "+g.hex(40),
	), "40 hex chars, same length as many secrets"))

	add(neg("uuids-in-fixture", "testdata/users.json", fmtLines(
		"{",
		`  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",`,
		`  "tenant": "9c858901-8a57-4791-81fe-4c455b099bc9"`,
		"}",
	), "UUIDs are high entropy and entirely public"))

	add(neg("sha256-checksums", "SHA256SUMS", fmtLines(
		g.hex(64)+"  release-linux-amd64.tar.gz",
		g.hex(64)+"  release-darwin-arm64.tar.gz",
	), "checksums are meant to be published"))

	add(neg("public-ssh-key", "deploy/authorized_keys", fmtLines(
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"+g.pick(alnum, 30)+" alice@laptop",
	), "a public key is not a secret"))

	add(neg("pem-public-certificate", "certs/server.crt", fmtLines(
		"-----BEGIN CERTIFICATE-----",
		g.pick(b64, 64),
		"-----END CERTIFICATE-----",
	), "certificates share the PEM envelope with private keys"))

	add(neg("public-key-pem", "certs/server.pub", fmtLines(
		"-----BEGIN PUBLIC KEY-----",
		g.pick(b64, 64),
		"-----END PUBLIC KEY-----",
	), "PUBLIC KEY must not match the private-key rule"))

	add(neg("documentation-mentioning-passwords", "docs/security.md", fmtLines(
		"# Security",
		"",
		"Never commit a password or an API key to this repository.",
		"Rotate any credential that reaches the remote, even briefly.",
	), "prose about secrets is not a secret"))

	add(neg("env-template-with-placeholders", ".env.example", fmtLines(
		"AWS_ACCESS_KEY_ID=",
		"AWS_SECRET_ACCESS_KEY=",
		"GITHUB_TOKEN=<your-token-here>",
		`DATABASE_PASSWORD="changeme"`,
	), "the template every repo ships"))

	add(neg("env-vars-read-not-assigned", "app/config.go", fmtLines(
		"package app",
		"",
		"var (",
		`	apiKey   = os.Getenv("API_KEY")`,
		`	password = os.Getenv("DB_PASSWORD")`,
		")",
	), "reading a credential is the correct pattern"))

	add(neg("short-assigned-values", "config/defaults.yaml", fmtLines(
		"timeout: 30s",
		`password: ""`,
		`token: "none"`,
		`api_key: "unset"`,
	), "below the 12-character threshold"))

	add(neg("base64-inline-image", "web/logo.css", fmtLines(
		".logo{background:url(data:image/png;base64,"+g.pick(b64, 120)+")}",
	), "base64 assets are high entropy and harmless"))

	add(neg("long-urls-with-query-strings", "docs/links.md", fmtLines(
		"See https://example.com/search?q=golang&page=2&sort=relevance&ref=docs&utm_source=readme",
	), "long high-entropy-looking URLs"))

	add(neg("go-module-hashes", "go.sum", fmtLines(
		"gopkg.in/yaml.v3 v3.0.1 h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=",
		"gopkg.in/yaml.v3 v3.0.1/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=",
	), "go.sum is skipped by path, and would be noise otherwise"))

	add(neg("minified-javascript", "dist/bundle.min.js", fmtLines(
		"!function(e,t){\"object\"==typeof exports?module.exports=t():e.lib=t()}(this,function(){return{"+g.pick(alnum, 80)+":1}});",
	), "minified bundles are skipped by path"))

	add(neg("lorem-ipsum", "content/post.md", fmtLines(
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do",
		"eiusmod tempor incididunt ut labore et dolore magna aliqua.",
	), "ordinary prose"))

	add(neg("example-aws-key-in-prose", "docs/iam.md", fmtLines(
		"# IAM",
		"",
		"Access key ids begin with the characters A K I A, followed by",
		"sixteen uppercase alphanumeric characters.",
	), "describing a credential shape without writing one"))

	add(neg("version-strings", "CHANGELOG.md", fmtLines(
		"## v1.24.3",
		"- bump dependency to v2.0.0-20240115123456-abcdef123456",
	), "pseudo-versions look like hashes"))

	add(neg("jwt-structure-described", "docs/auth.md", fmtLines(
		"A JWT is three base64url segments separated by dots:",
		"header, payload and signature.",
	), "describing a JWT without including one"))

	add(neg("terraform-with-variable-reference", "main.tf", fmtLines(
		`provider "aws" {`,
		"  region     = var.region",
		"  access_key = var.aws_access_key",
		"}",
	), "the correct way to write the Terraform case above"))

	add(neg("kubernetes-secret-ref", "k8s/deployment.yaml", fmtLines(
		"env:",
		"  - name: AWS_ACCESS_KEY_ID",
		"    valueFrom:",
		"      secretKeyRef:",
		"        name: aws-creds",
		"        key: access-key-id",
	), "a reference to a secret is not a secret"))

	add(neg("ci-with-secret-interpolation", ".github/workflows/ci.yml", fmtLines(
		"jobs:",
		"  build:",
		"    env:",
		"      AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}",
	), "the correct way to write the CI case above"))

	add(neg("random-prose-high-entropy-words", "words.txt", fmtLines(
		"antidisestablishmentarianism",
		"pneumonoultramicroscopicsilicovolcanoconiosis",
	), "long words are not high entropy per character"))

	add(neg("test-placeholder-tokens", "test/fixtures/tokens.json", fmtLines(
		"{",
		`  "token": "test-token",`,
		`  "api_key": "fake-key-01"`,
		"}",
	), "obvious placeholders, under the length threshold"))

	add(neg("css-colour-hashes", "web/theme.css", fmtLines(
		":root{--bg:#1a1a2e;--fg:#eaeaea;--accent:#0f3460;--warn:#e94560}",
	), "hex colours"))

	add(neg("binary-like-content", "assets/data.bin", "\x00\x01\x02binary\x00content\x00"+g.pick(alnum, 40),
		"NUL bytes mark it binary and it must be skipped"))

	add(neg("empty-file", "empty.txt", "", "degenerate input"))

	add(neg("license-text", "LICENSE", fmtLines(
		"Apache License",
		"Version 2.0, January 2004",
		"http://www.apache.org/licenses/",
	), "a file present in most repositories"))

	return cases
}
