// Turning a secret into environment variables for a command, without letting the sender
// choose variables that make programs load code, run commands, read other files, trust other
// certificates or send requests elsewhere (which could carry the user's own credentials,
// inherited from their environment, to the sender). The rules are deliberately broad: a
// refused name is an inconvenience, an allowed dangerous one could run code or leak keys.

const NAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const ASSIGNMENT = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]{0,63})\s*=\s*(.*)$/;
const MAX_VARIABLES = 100;

/** Variables a secret may never set (all comparisons are upper-case). */
const DENY_EXACT = new Set([
  // shells and the process itself
  "PATH", "HOME", "SHELL", "USER", "LOGNAME", "PWD", "OLDPWD", "IFS", "ENV", "CDPATH", "FPATH", "PS1", "PS2",
  "PS3", "PS4", "PROMPT", "RPROMPT", "PROMPT_COMMAND", "SHELLOPTS", "BASHOPTS", "GLOBIGNORE", "INPUTRC", "MAIL",
  "MAILPATH", "MAILCHECK", "HISTFILE", "ZDOTDIR", "TMPDIR", "TEMP", "TMP", "EDITOR", "VISUAL", "TERM", "TERMINFO",
  "TERMINFO_DIRS", "TERMCAP", "COMSPEC", "PATHEXT", "PSMODULEPATH", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
  "PROGRAMDATA", "SYSTEMROOT", "WINDIR",
  // the C library, locales, name resolution
  "LANG", "LANGUAGE", "NLSPATH", "LOCPATH", "GCONV_PATH", "GLIBC_TUNABLES", "HOSTALIASES", "RESOLV_HOST_CONF",
  "RES_OPTIONS", "LOCALDOMAIN", "TZDIR", "LIBPATH", "SHLIB_PATH",
  // compilers and build tools (make runs these through a shell)
  "CC", "CXX", "CPP", "LD", "AR", "AS", "NM", "RANLIB", "STRIP", "OBJCOPY", "OBJDUMP", "YACC", "LEX", "FC", "F77",
  "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS", "MAKEFILES", "MAKE",
  "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "LIBRARY_PATH", "ACLOCAL_PATH", "CLASSPATH", "JAVA_HOME",
  "GOFLAGS", "GOPROXY", "GOPATH", "GOROOT", "GOTOOLCHAIN", "GONOSUMDB", "GONOSUMCHECK", "GONOPROXY", "GOINSECURE",
  "GOPRIVATE", "GOSUMDB", "GOENV", "GOBIN", "GOCACHE", "GOMODCACHE", "GOEXPERIMENT", "GODEBUG", "GOWORK", "GOVCS",
  "GOAUTH", "GOTMPDIR", "GOCOVERDIR", "VIRTUAL_ENV", "IRBRC", "TCLLIBPATH", "EMACSLOADPATH", "EXINIT",
  // certificates, TLS and networking
  "REQUESTS_CA_BUNDLE", "WGETRC", "NETRC", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY",
  "DOCKER_CONTEXT", "BUILDKIT_HOST", "CONTAINER_HOST", "KUBECONFIG", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY",
  "XMODIFIERS",
  // credentials helpers and config files of other tools
  "SSH_AUTH_SOCK", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "SSH_SK_PROVIDER", "SSH_SK_HELPER", "SSH_PKCS11_HELPER",
  "GNUPGHOME", "GPG_AGENT_INFO", "GOOGLE_APPLICATION_CREDENTIALS", "CLOUDSDK_CONFIG", "CLOUDSDK_PYTHON",
  "BOTO_CONFIG", "RCLONE_CONFIG", "GH_CONFIG_DIR",
  // where cloud SDKs fetch credentials from, or which identity provider they trust
  "GCE_METADATA_HOST", "GCE_METADATA_IP", "GCE_METADATA_ROOT", "IDENTITY_ENDPOINT", "IDENTITY_HEADER", "MSI_ENDPOINT",
  "MSI_SECRET", "IMDS_ENDPOINT", "AZURE_AUTHORITY_HOST", "AZURE_POD_IDENTITY_AUTHORITY_HOST",
  "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "GH_HOST", "GITHUB_API_URL", "GITHUB_SERVER_URL",
]);

const DENY_PREFIX = [
  // dynamic linkers and allocators
  "LD_", "DYLD_", "MALLOC_", "LC_",
  // this tool, version control and remote shells
  "OSSS_", "GIT_", "HG", "SVN_", "CVS", "RSYNC_", "SUDO_",
  // language runtimes and package managers
  "NODE_", "NPM_CONFIG_", "YARN_", "PNPM_", "BUN_", "DENO_", "COREPACK_", "ELECTRON_", "NVM_", "PYTHON", "PIP_",
  "PIPX_", "UV_", "CONDA", "PYENV_", "POETRY_", "PDM_", "PIPENV_", "RUBY", "GEM_", "BUNDLE_", "PERL", "PHP", "_JAVA",
  "GRADLE_", "ORG_GRADLE_", "MAVEN_", "DOTNET_", "CORECLR_", "COMPLUS_", "MSBUILD", "CGO_", "CARGO_", "RUST",
  "LUA_", "R_", "JULIA_", "ERL_", "TCL_", "VIM", "CMAKE_", "PKG_CONFIG", "CCACHE_", "DISTCC_", "TF_CLI_ARGS",
  "ANSIBLE_", "HELM_PLUGINS", "NUGET_",
  // shells, pagers, terminals
  "BASH", "ZSH", "LESS",
  // TLS libraries and HTTP clients
  "SSL", "OPENSSL_", "CURL_", "WGET",
  // desktop libraries that load plugins or connect to buses
  "GTK_", "QT_", "GIO_", "GST_", "GDK_", "LIBGL_", "MESA_", "VK_", "DBUS_", "XDG_",
  // cloud endpoints and credential providers
  "AWS_ENDPOINT", "AWS_CONTAINER_", "AWS_EC2_METADATA", "ECS_CONTAINER_METADATA", "GCE_METADATA",
  "CLOUDSDK_API_ENDPOINT_OVERRIDES",
];

const DENY_SUFFIX = [
  // paths, homes and files: values here make programs read files the sender chose
  // (for example a script in the repository an agent is working in)
  "PATH", "PATHS", "HOME", "_DIR", "_DIRS", "_FILE", "_FILES", "RC",
  // commands, hooks and option strings
  "_COMMAND", "_CMD", "_HOOK", "_HOOKS", "_OPTS", "_OPTIONS", "SHELL", "PAGER", "EDITOR", "BROWSER",
  // traffic and trust: proxies, certificates and API endpoints (OPENAI_BASE_URL,
  // ANTHROPIC_BASE_URL, AZURE_OPENAI_ENDPOINT, HF_ENDPOINT, ...)
  "_PROXY", "CA_BUNDLE", "_CA_CERTS", "_CERT_FILE", "_BASE_URL", "_API_BASE", "_API_HOST", "_ENDPOINT", "_ENDPOINT_URL",
  "_ENDPOINTS",
];

/** Common names that match a rule above but only select a mode or carry a registry token. */
const ALLOW_EXACT = new Set([
  "NODE_ENV", "NODE_AUTH_TOKEN", "CARGO_REGISTRY_TOKEN", "YARN_NPM_AUTH_TOKEN", "UV_PUBLISH_TOKEN", "POETRY_PYPI_TOKEN_PYPI",
  "NUGET_API_KEY", "NUGET_AUTH_TOKEN",
]);

export function isSafeVariableName(name: string): boolean {
  if (!NAME.test(name)) return false;
  const upper = name.toUpperCase();
  if (ALLOW_EXACT.has(upper)) return true;
  if (DENY_EXACT.has(upper)) return false;
  if (DENY_PREFIX.some((p) => upper.startsWith(p))) return false;
  if (DENY_SUFFIX.some((s) => upper.endsWith(s))) return false;
  return true;
}

export interface EnvSecret {
  /** Variables that may be exported, in order. */
  vars: Map<string, string>;
  /** Names the secret contained but that will never be exported. */
  refused: string[];
}

/** dotenv-style values: quotes are removed, `\n` is expanded in double quotes, ` #` starts a comment. */
function parseValue(raw: string): string {
  const v = raw.trim();
  const quote = v[0];
  if ((quote === '"' || quote === "'") && v.length >= 2 && v.endsWith(quote)) {
    const inner = v.slice(1, -1);
    return quote === '"' ? inner.replace(/\\n/g, "\n").replace(/\\r/g, "\r").replace(/\\t/g, "\t").replace(/\\"/g, '"') : inner;
  }
  const comment = v.search(/\s#/);
  return (comment >= 0 ? v.slice(0, comment) : v).trimEnd();
}

/**
 * Reads a dotenv-style secret. Returns null unless every non-empty, non-comment line is a
 * KEY=VALUE assignment (at most 100); anything else is passed as one plain secret instead.
 */
export function parseEnvSecret(text: string): EnvSecret | null {
  const vars = new Map<string, string>();
  const refused: string[] = [];
  let count = 0;
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const m = ASSIGNMENT.exec(trimmed);
    if (!m || ++count > MAX_VARIABLES) return null;
    const name = m[1] as string;
    const value = parseValue(m[2] as string);
    // NUL can't be passed in an environment variable.
    if (isSafeVariableName(name) && !value.includes("\0")) vars.set(name, value);
    else if (!refused.includes(name)) refused.push(name);
  }
  return vars.size + refused.length > 0 ? { vars, refused } : null;
}

/** Shorter values are too likely to match ordinary output; encoded forms need more length. */
const MIN_REDACT = 4;
const MIN_ENCODED = 6;

function encodings(value: string): string[] {
  const out = [JSON.stringify(value).slice(1, -1)];
  try {
    out.push(encodeURIComponent(value));
  } catch {
    // lone surrogates can't be URL-encoded
  }
  const bytes = Buffer.from(value, "utf8");
  const b64 = bytes.toString("base64");
  const hex = bytes.toString("hex");
  out.push(b64, b64.replace(/=+$/, ""), bytes.toString("base64url"), hex, hex.toUpperCase());
  return out;
}

/**
 * Best-effort redaction of secret values (4 characters or longer) from text, including their
 * JSON-escaped, URL-encoded, base64 and hex forms and each line of multi-line values. Defence
 * in depth only: a program can still transform or leak a value it was given.
 */
export function makeRedactor(values: Iterable<string>): (text: string) => string {
  const needles = new Set<string>();
  for (const value of values) {
    for (const part of [value, ...value.split(/\r?\n/)]) {
      const p = part.trim();
      if (p.length < MIN_REDACT) continue;
      needles.add(p);
      for (const form of encodings(p)) if (form.length >= MIN_ENCODED) needles.add(form);
    }
  }
  const sorted = [...needles].sort((a, b) => b.length - a.length);
  return (text: string) => {
    let out = text;
    for (const needle of sorted) if (out.includes(needle)) out = out.split(needle).join("[redacted]");
    return out;
  };
}
