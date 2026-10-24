import { describe, expect, it } from "vitest";
import { isSafeVariableName, makeRedactor, parseEnvSecret } from "../../src/cli/envsecret";

describe("isSafeVariableName", () => {
  it("allows ordinary credential names", () => {
    for (const name of [
      "API_KEY",
      "DATABASE_URL",
      "AWS_ACCESS_KEY_ID",
      "AWS_SECRET_ACCESS_KEY",
      "AWS_PROFILE",
      "GITHUB_TOKEN",
      "GH_TOKEN",
      "NPM_TOKEN",
      "OPENAI_API_KEY",
      "CLOUDFLARE_API_TOKEN",
      "STRIPE_SECRET_KEY",
      "PGPASSWORD",
      "NODE_ENV",
      "NODE_AUTH_TOKEN",
      "CARGO_REGISTRY_TOKEN",
      "NUGET_API_KEY",
      "lower_case_name",
      "_UNDERSCORE",
    ]) {
      expect(isSafeVariableName(name), name).toBe(true);
    }
  });

  it("refuses names that change how programs load code, run commands, trust or route", () => {
    for (const name of [
      "PATH",
      "Path",
      "HOME",
      "SHELL",
      "IFS",
      "ENV",
      "BASH_ENV",
      "BASH_FUNC_ls%%",
      "PROMPT_COMMAND",
      "PS1",
      "PS4",
      "TMPDIR",
      "LD_PRELOAD",
      "LD_LIBRARY_PATH",
      "DYLD_INSERT_LIBRARIES",
      "GLIBC_TUNABLES",
      "GCONV_PATH",
      "MALLOC_CONF",
      "NODE_OPTIONS",
      "NODE_PATH",
      "NODE_EXTRA_CA_CERTS",
      "NODE_TLS_REJECT_UNAUTHORIZED",
      "npm_config_registry",
      "YARN_YARN_PATH",
      "ELECTRON_RUN_AS_NODE",
      "PYTHONPATH",
      "PYTHONSTARTUP",
      "PIP_INDEX_URL",
      "UV_INDEX_URL",
      "VIRTUAL_ENV",
      "RUBYOPT",
      "PERL5OPT",
      "PERL5DB",
      "PHPRC",
      "JAVA_TOOL_OPTIONS",
      "_JAVA_OPTIONS",
      "MAVEN_OPTS",
      "CLASSPATH",
      "DOTNET_STARTUP_HOOKS",
      "CORECLR_PROFILER_PATH",
      "GOFLAGS",
      "GOPROXY",
      "CGO_LDFLAGS",
      "CARGO_BUILD_RUSTC_WRAPPER",
      "RUSTC_WRAPPER",
      "LUA_INIT",
      "R_PROFILE_USER",
      "ERL_FLAGS",
      "CC",
      "MAKEFLAGS",
      "CMAKE_C_COMPILER_LAUNCHER",
      "GIT_SSH_COMMAND",
      "GIT_CONFIG_COUNT",
      "SVN_SSH",
      "RSYNC_RSH",
      "SSH_AUTH_SOCK",
      "SSH_ASKPASS",
      "SSH_SK_PROVIDER",
      "SUDO_ASKPASS",
      "EDITOR",
      "GIT_EDITOR",
      "PAGER",
      "LESSOPEN",
      "BROWSER",
      "HTTP_PROXY",
      "https_proxy",
      "ALL_PROXY",
      "NO_PROXY",
      "SSL_CERT_FILE",
      "SSLKEYLOGFILE",
      "OPENSSL_CONF",
      "CURL_CA_BUNDLE",
      "REQUESTS_CA_BUNDLE",
      "AWS_CA_BUNDLE",
      "AWS_SHARED_CREDENTIALS_FILE",
      "GOOGLE_APPLICATION_CREDENTIALS",
      "DOCKER_HOST",
      "KUBECONFIG",
      "XDG_CONFIG_HOME",
      "DISPLAY",
      "GTK_MODULES",
      "VIMINIT",
      "TAR_OPTIONS",
      "DEPLOY_CMD",
      "OSSS_SECRET",
      "OSSS_HOME",
      // endpoints and credential providers that could send the user's own credentials elsewhere
      "OPENAI_BASE_URL",
      "ANTHROPIC_BASE_URL",
      "OPENAI_API_BASE",
      "AZURE_OPENAI_ENDPOINT",
      "HF_ENDPOINT",
      "AWS_ENDPOINT_URL",
      "AWS_ENDPOINT_URL_S3",
      "AWS_CONTAINER_CREDENTIALS_FULL_URI",
      "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
      "AWS_EC2_METADATA_SERVICE_ENDPOINT",
      "GCE_METADATA_HOST",
      "IDENTITY_ENDPOINT",
      "MSI_ENDPOINT",
      "AZURE_AUTHORITY_HOST",
      "GH_HOST",
      "GITHUB_API_URL",
      "ACTIONS_ID_TOKEN_REQUEST_URL",
      "NUGET_NETCORE_PLUGIN_PATHS",
      "NUGET_PLUGIN_PATHS",
      "NUGET_PACKAGES",
    ]) {
      expect(isSafeVariableName(name), name).toBe(false);
    }
  });

  it("refuses malformed names", () => {
    for (const name of ["", "1ABC", "A-B", "A B", "A=B", "Ä", "A".repeat(65)]) expect(isSafeVariableName(name), name).toBe(false);
  });
});

describe("parseEnvSecret", () => {
  it("reads dotenv-style lines", () => {
    const parsed = parseEnvSecret(
      [
        "# deploy settings",
        "API_KEY=abc123",
        "export TOKEN = 'single quoted # not a comment'",
        'MULTI="line one\\nline two"',
        "PLAIN=value # trailing comment",
        "HASH=abc#def",
        "EMPTY=",
        "",
      ].join("\r\n"),
    );
    expect(parsed).not.toBeNull();
    expect(Object.fromEntries(parsed!.vars)).toEqual({
      API_KEY: "abc123",
      TOKEN: "single quoted # not a comment",
      MULTI: "line one\nline two",
      PLAIN: "value",
      HASH: "abc#def",
      EMPTY: "",
    });
    expect(parsed!.refused).toEqual([]);
  });

  it("lists refused names once and never exports them", () => {
    const parsed = parseEnvSecret("API_KEY=ok\nNODE_OPTIONS=--require=/tmp/x.js\nLD_PRELOAD=/tmp/x.so\nNODE_OPTIONS=again");
    expect([...parsed!.vars.keys()]).toEqual(["API_KEY"]);
    expect(parsed!.refused).toEqual(["NODE_OPTIONS", "LD_PRELOAD"]);
  });

  it("refuses values containing NUL", () => {
    const parsed = parseEnvSecret("A=fine\nB=bad\u0000value");
    expect([...parsed!.vars.keys()]).toEqual(["A"]);
    expect(parsed!.refused).toEqual(["B"]);
  });

  it("treats anything that isn't only assignments as one plain secret", () => {
    expect(parseEnvSecret("correct horse battery staple")).toBeNull();
    expect(parseEnvSecret("API_KEY=abc\nthis line is not an assignment")).toBeNull();
    expect(parseEnvSecret("-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----")).toBeNull();
    expect(parseEnvSecret("")).toBeNull();
    expect(parseEnvSecret("# only a comment\n\n")).toBeNull();
  });

  it("treats more than 100 assignments as a plain secret", () => {
    const lines = Array.from({ length: 101 }, (_, i) => `VAR_${i}=x`);
    expect(parseEnvSecret(lines.slice(0, 100).join("\n"))?.vars.size).toBe(100);
    expect(parseEnvSecret(lines.join("\n"))).toBeNull();
  });
});

describe("makeRedactor", () => {
  const value = "s3cr3t-token-value";

  it("redacts the value and its common encodings", () => {
    const redact = makeRedactor([value]);
    const b64 = Buffer.from(value).toString("base64");
    expect(redact(`token=${value}\n`)).toBe("token=[redacted]\n");
    expect(redact(`{"t":"${value}"}`)).toBe('{"t":"[redacted]"}');
    expect(redact(`b64 ${b64}`)).toBe("b64 [redacted]");
    expect(redact(`hex ${Buffer.from(value).toString("hex")}`)).toBe("hex [redacted]");
    expect(redact(`HEX ${Buffer.from(value).toString("hex").toUpperCase()}`)).toBe("HEX [redacted]");
    expect(redact("nothing to hide")).toBe("nothing to hide");
  });

  it("redacts URL-encoded and JSON-escaped forms of values with special characters", () => {
    const special = 'p@ss "word"/1';
    const redact = makeRedactor([special]);
    expect(redact(`q=${encodeURIComponent(special)}`)).toBe("q=[redacted]");
    expect(redact(JSON.stringify({ p: special }))).toBe('{"p":"[redacted]"}');
  });

  it("redacts each line of a multi-line value", () => {
    const pem = "-----BEGIN KEY-----\nAAAABBBBCCCCDDDD\n-----END KEY-----";
    const redact = makeRedactor([pem]);
    expect(redact("line: AAAABBBBCCCCDDDD")).toBe("line: [redacted]");
    expect(redact(pem)).toBe("[redacted]");
  });

  it("leaves values under 4 characters alone and prefers the longest match", () => {
    const redact = makeRedactor(["abc", "1234", "secret", "secret-longer"]);
    expect(redact("abc 1234 secret secret-longer")).toBe("abc [redacted] [redacted] [redacted]");
  });
});
