package redteam

import (
	"fmt"
	"strings"
)

// positives plants one credential per case, in the kind of file it really
// shows up in. The contexts are chosen to be awkward on purpose: config
// formats, CI files, test fixtures and documentation are where credentials
// actually leak, not tidy Go source.
func positives(g generator) []Case {
	var cases []Case
	add := func(c Case) { cases = append(cases, c) }

	// --- AWS -------------------------------------------------------------

	k := g.awsKeyID()
	add(mk("aws-key-in-dotenv", ".env", "aws-access-key-id", k, fmtLines(
		"# production credentials",
		"DATABASE_URL=postgres://localhost:5432/app",
		"AWS_ACCESS_KEY_ID="+k,
		"AWS_REGION=us-east-1",
	), "the most common leak: a committed .env"))

	k = g.awsKeyID()
	add(mk("aws-key-in-terraform", "main.tf", "aws-access-key-id", k, fmtLines(
		`provider "aws" {`,
		`  region     = "us-east-1"`,
		`  access_key = "`+k+`"`,
		`}`,
	), "hardcoded provider credentials"))

	k = g.awsKeyID()
	add(mk("aws-key-in-yaml", "deploy/values.yaml", "aws-access-key-id", k, fmtLines(
		"image:",
		"  repository: acme/api",
		"env:",
		"  - name: AWS_ACCESS_KEY_ID",
		"    value: "+k,
	), "unquoted YAML scalar"))

	k = g.awsKeyID()
	add(mk("aws-key-in-markdown", "docs/setup.md", "aws-access-key-id", k, fmtLines(
		"## Local setup",
		"",
		"Export your credentials:",
		"",
		"```sh",
		"export AWS_ACCESS_KEY_ID="+k,
		"```",
	), "credentials pasted into documentation"))

	k = g.awsKeyID()
	add(mk("aws-key-in-ci-workflow", ".github/workflows/deploy.yml", "aws-access-key-id", k, fmtLines(
		"jobs:",
		"  deploy:",
		"    runs-on: ubuntu-latest",
		"    env:",
		"      AWS_ACCESS_KEY_ID: "+k,
		"    steps:",
		"      - uses: actions/checkout@v4",
	), "CI config, where a secret should have been a repository secret"))

	s := g.awsSecret()
	add(mk("aws-secret-in-dotenv", ".env.production", "aws-secret-access-key", s, fmtLines(
		"AWS_SECRET_ACCESS_KEY="+s,
		"LOG_LEVEL=info",
	), "the secret half, which has no distinctive prefix"))

	s = g.awsSecret()
	add(mk("aws-secret-lowercase-key", "config/app.ini", "aws-secret-access-key", s, fmtLines(
		"[aws]",
		"aws_secret_access_key = "+s,
	), "lowercase, spaced assignment"))

	s = g.awsSecret()
	add(mk("aws-secret-dotted-key", "settings.py", "aws-secret-access-key", s, fmtLines(
		"DEBUG = False",
		`AWS.SECRET.ACCESS.KEY = "`+s+`"`,
	), "dot-separated variant of the key name"))

	// --- GitHub ----------------------------------------------------------

	for _, kind := range []string{"ghp", "gho", "ghu", "ghs", "ghr"} {
		tok := g.githubToken(kind)
		add(mk("github-token-"+kind, "scripts/release.sh", "github-token", tok, fmtLines(
			"#!/bin/sh",
			"set -eu",
			`curl -H "Authorization: token `+tok+`" \`,
			"  https://api.github.com/user/repos",
		), fmt.Sprintf("%s_ token class", kind)))
	}

	tok := g.githubToken("ghp")
	add(mk("github-token-in-url", "Makefile", "github-token", tok, fmtLines(
		"deps:",
		"\tgit clone https://"+tok+"@github.com/acme/private.git",
	), "token embedded in a clone URL"))

	tok = g.githubToken("ghp")
	add(mk("github-token-in-json", ".npmrc.json", "github-token", tok, fmtLines(
		"{",
		`  "registry": "https://npm.pkg.github.com",`,
		`  "token": "`+tok+`"`,
		"}",
	), "JSON config"))

	tok = g.githubToken("ghs")
	add(mk("github-token-in-test-fixture", "internal/api/testdata/auth.json", "github-token", tok, fmtLines(
		"{",
		`  "description": "fixture for the auth handler",`,
		`  "credential": "`+tok+`"`,
		"}",
	), "test fixtures are a classic blind spot"))

	// --- Other providers --------------------------------------------------

	sl := g.slackToken("b")
	add(mk("slack-bot-token", "bot/config.yaml", "slack-token", sl, fmtLines(
		"slack:",
		"  bot_token: "+sl,
		"  channel: '#alerts'",
	), "Slack bot token"))

	sl = g.slackToken("p")
	add(mk("slack-user-token", "integrations/slack.go", "slack-token", sl, fmtLines(
		"package integrations",
		"",
		`const userToken = "`+sl+`"`,
	), "Slack user token hardcoded in Go"))

	st := g.stripeKey("sk", "live")
	add(mk("stripe-live-key", "billing/client.js", "stripe-secret-key", st, fmtLines(
		"const stripe = require('stripe')(",
		"  '"+st+"'",
		");",
	), "a live Stripe key split across lines"))

	st = g.stripeKey("rk", "live")
	add(mk("stripe-restricted-key", ".env.local", "stripe-secret-key", st, fmtLines(
		"STRIPE_RESTRICTED_KEY="+st,
	), "restricted keys are still credentials"))

	gk := g.googleKey()
	add(mk("google-api-key-in-android-config", "android/app/google-services.json", "google-api-key", gk, fmtLines(
		"{",
		`  "api_key": [ { "current_key": "`+gk+`" } ]`,
		"}",
	), "Google services config"))

	gk = g.googleKey()
	add(mk("google-api-key-in-html", "web/index.html", "google-api-key", gk, fmtLines(
		"<!doctype html>",
		`<script src="https://maps.googleapis.com/maps/api/js?key=`+gk+`"></script>`,
	), "key in a script URL"))

	sg := g.gatewayToken()
	add(mk("gateway-token-committed", "docs/onboarding.md", "gateway-token", sg, fmtLines(
		"Add the gateway remote:",
		"",
		"    git remote add gateway http://"+sg+"@gateway.internal/acme/api.git",
	), "our own token class, dogfooded"))

	// --- Private keys -----------------------------------------------------

	for _, kind := range []string{"RSA ", "EC ", "OPENSSH ", "PGP ", ""} {
		header := "-----BEGIN " + kind + "PRIVATE KEY-----"
		name := "private-key-" + strings.ToLower(strings.TrimSpace(kind))
		if kind == "" {
			name = "private-key-generic"
		}
		add(mk(name, "deploy/id_key", "private-key", header, fmtLines(
			header,
			g.pick(b64, 64),
			g.pick(b64, 64),
			"-----END "+kind+"PRIVATE KEY-----",
		), "private key material, "+name))
	}

	hdr := "-----BEGIN RSA PRIVATE KEY-----"
	add(mk("private-key-inside-yaml", "k8s/secret.yaml", "private-key", hdr, fmtLines(
		"apiVersion: v1",
		"kind: Secret",
		"stringData:",
		"  tls.key: |",
		"    "+hdr,
		"    "+g.pick(b64, 60),
	), "key embedded in a Kubernetes manifest"))

	// --- JWTs --------------------------------------------------------------

	j := g.jwt()
	add(mk("jwt-in-source", "auth/session.go", "jwt", j, fmtLines(
		"package auth",
		"",
		`var serviceToken = "`+j+`"`,
	), "a signed JWT is a bearer credential"))

	j = g.jwt()
	add(mk("jwt-in-http-fixture", "test/fixtures/request.http", "jwt", j, fmtLines(
		"GET /api/me HTTP/1.1",
		"Authorization: Bearer "+j,
	), "captured request with a live token"))

	// --- Generic assigned secrets -------------------------------------------

	pw := g.pick(alnum, 20)
	add(mk("password-assignment", "config/database.yml", "generic-assigned-secret", pw, fmtLines(
		"production:",
		"  adapter: postgresql",
		`  password: "`+pw+`"`,
	), "no recognisable shape; only the variable name gives it away"))

	pw = g.pick(alnum, 24)
	add(mk("api-key-assignment", "client/settings.json", "generic-assigned-secret", pw, fmtLines(
		"{",
		`  "api_key": "`+pw+`"`,
		"}",
	), "generic api_key"))

	pw = g.pick(urlSafe, 32)
	add(mk("secret-assignment-in-python", "app/config.py", "generic-assigned-secret", pw, fmtLines(
		"import os",
		"",
		`SECRET_KEY = "`+pw+`"`,
	), "Django-style secret key"))

	pw = g.pick(alnum, 18)
	add(mk("auth-assignment-in-toml", "config.toml", "generic-assigned-secret", pw, fmtLines(
		"[server]",
		`auth = "`+pw+`"`,
	), "TOML assignment"))

	pw = g.hex(40)
	add(mk("token-assignment-hex", "ci/vars.sh", "generic-assigned-secret", pw, fmtLines(
		`export TOKEN="`+pw+`"`,
	), "hex-encoded token"))

	// --- Awkward placements -------------------------------------------------

	k = g.awsKeyID()
	add(mk("secret-on-a-very-long-line", "dist/config.js", "aws-access-key-id", k, fmtLines(
		"module.exports={region:'us-east-1',retries:3,timeout:30000,endpoint:'https://api.example.com/v1/resource',accessKeyId:'"+k+"',maxSockets:50};",
	), "minified-style long line"))

	k = g.awsKeyID()
	add(mk("secret-after-many-clean-lines", "internal/app/server.go", "aws-access-key-id", k, fmtLines(
		append(repeat("// routine comment line", 40), `const key = "`+k+`"`)...,
	), "buried deep in a file"))

	k = g.awsKeyID()
	add(mk("secret-in-deleted-then-readded", "restored.env", "aws-access-key-id", k, fmtLines(
		"# restored from backup",
		"AWS_ACCESS_KEY_ID="+k,
	), "re-added after a previous removal"))

	tok = g.githubToken("ghp")
	add(mk("two-secrets-one-file-first", "multi.env", "github-token", tok, fmtLines(
		"GITHUB_TOKEN="+tok,
		"AWS_ACCESS_KEY_ID="+g.awsKeyID(),
	), "several credentials in one file"))

	k = g.awsKeyID()
	add(mk("secret-with-crlf-endings", "windows.env", "aws-access-key-id", k,
		"# windows line endings\r\nAWS_ACCESS_KEY_ID="+k+"\r\n",
		"CRLF must not defeat line splitting"))

	k = g.awsKeyID()
	add(mk("secret-in-commented-line", "old.tf", "aws-access-key-id", k, fmtLines(
		"# access_key was rotated, old value kept for reference:",
		"# "+k,
	), "commented out is still committed"))

	tok = g.githubToken("ghp")
	add(mk("secret-in-jsonl-log", "logs/debug.jsonl", "github-token", tok, fmtLines(
		`{"level":"debug","msg":"calling api","auth":"`+tok+`"}`,
	), "credential captured in a committed log"))

	st = g.stripeKey("sk", "test")
	add(mk("stripe-test-key", "test/payments_test.go", "stripe-secret-key", st, fmtLines(
		"package payments",
		"",
		`const testKey = "`+st+`"`,
	), "test keys are lower risk but still reportable"))

	k = g.awsKeyID()
	add(mk("secret-in-dockerfile", "Dockerfile", "aws-access-key-id", k, fmtLines(
		"FROM golang:1.23",
		"ENV AWS_ACCESS_KEY_ID="+k,
		"RUN go build ./...",
	), "build-time credential baked into an image"))

	k = g.awsKeyID()
	add(mk("secret-in-docker-compose", "docker-compose.yml", "aws-access-key-id", k, fmtLines(
		"services:",
		"  api:",
		"    environment:",
		"      AWS_ACCESS_KEY_ID: "+k,
	), "compose file"))

	return cases
}

// repeat returns n copies of s, for building padded fixtures.
func repeat(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}

// morePositives extends the corpus past the fifty planted secrets the
// detection-rate claim rests on. Split out only to keep each function
// readable.
func morePositives(g generator) []Case {
	var cases []Case
	add := func(c Case) { cases = append(cases, c) }

	pw := g.pick(alnum, 22)
	add(mk("client-secret-assignment", "oauth/config.json", "generic-assigned-secret", pw, fmtLines(
		"{",
		`  "client_id": "acme-web",`,
		`  "client_secret": "`+pw+`"`,
		"}",
	), "OAuth client secret, keyword with a prefix"))

	pw = g.pick(alnum, 16)
	add(mk("pwd-abbreviation", "legacy/db.properties", "generic-assigned-secret", pw, fmtLines(
		"db.host=localhost",
		`db.pwd="`+pw+`"`,
	), "abbreviated keyword"))

	pw = g.pick(urlSafe, 28)
	add(mk("credential-in-gradle-properties", "gradle.properties", "generic-assigned-secret", pw, fmtLines(
		"org.gradle.jvmargs=-Xmx2g",
		`publishCredential="`+pw+`"`,
	), "keyword with a suffix in a build file"))

	k := g.awsKeyID()
	add(mk("aws-key-in-credentials-csv", "new_user_credentials.csv", "aws-access-key-id", k, fmtLines(
		"User name,Access key ID,Secret access key",
		"deploy-bot,"+k+","+g.awsSecret(),
	), "the CSV the AWS console hands you, committed verbatim"))

	tok := g.githubToken("ghp")
	add(mk("github-token-in-git-credentials", ".git-credentials", "github-token", tok, fmtLines(
		"https://alice:"+tok+"@github.com",
	), "git's own credential store, committed by accident"))

	tok = g.githubToken("gho")
	add(mk("github-token-in-netrc", ".netrc", "github-token", tok, fmtLines(
		"machine github.com",
		"  login alice",
		"  password "+tok,
	), "netrc format"))

	j := g.jwt()
	add(mk("jwt-in-cookie-fixture", "test/fixtures/cookies.txt", "jwt", j, fmtLines(
		"session="+j+"; Path=/; HttpOnly",
	), "a session cookie captured into a fixture"))

	st := g.stripeKey("sk", "live")
	add(mk("stripe-key-in-env", ".env.staging", "stripe-secret-key", st, fmtLines(
		"STRIPE_SECRET_KEY="+st,
		"STRIPE_WEBHOOK_SECRET=whsec_placeholder",
	), "alongside a non-matching sibling"))

	gk := g.googleKey()
	add(mk("google-key-in-properties", "app/local.properties", "google-api-key", gk, fmtLines(
		"sdk.dir=/opt/android-sdk",
		"MAPS_API_KEY="+gk,
	), "Android local.properties"))

	sl := g.slackToken("a")
	add(mk("slack-app-token-in-env", ".env.bot", "slack-token", sl, fmtLines(
		"SLACK_APP_TOKEN="+sl,
	), "app-level token"))

	return cases
}
