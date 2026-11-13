# MCP Server <Badge text="Experimental" type="warning"/>

Atlantis can serve a [Model Context Protocol](https://modelcontextprotocol.io) endpoint so that an AI assistant can read the state of a pull request and, if you allow it, run `plan`, `apply` and `unlock` on it.

The MCP server is off by default. Enabling it changes nothing for people who use Atlantis through pull request comments. See the [MCP experiment](experiments.md#mcp-server) for its status.

::: warning GitHub only
The MCP server currently supports GitHub, including GitHub Enterprise.
:::

## How it works

Every MCP call is made by a known user and runs through the same path as a pull request comment:

- The MCP client discovers Atlantis OAuth, registers itself, and opens a browser. The user reviews the client and callback address, then signs in with GitHub. The client obtains and refreshes access tokens automatically.
- Clients without MCP OAuth support can still use a personal token from the manual login page.
- A command runs as that user. The [team allowlist](server-configuration.md#gh-team-allowlist), [command requirements](command-requirements.md), locks, hooks and `--allow-commands` apply exactly as they do for a comment.
- Atlantis first comments on the pull request who ran which command, then posts the result as usual. A reviewer sees everything the assistant did.
- On every call Atlantis asks GitHub for the user's permission on the repository. Reading requires read permission. Running a command requires write permission.

The MCP server grants no permission that the user does not already have through comments.

## Enabling

1. Create a GitHub OAuth App, or use the client credentials of a GitHub App. Set its authorization callback URL to `<atlantis-url>/auth/github/callback`. Atlantis requests no scopes; the login only proves who the user is.
2. Generate a signing secret of at least 32 characters, for example with `openssl rand -hex 32`.
3. Configure the server:

```yaml
experiments:
  - mcp
mcp-enabled: true
mcp-gh-oauth-client-id: Ov23li...
```

```bash
ATLANTIS_MCP_TOKEN_SECRET=...
ATLANTIS_MCP_GH_OAUTH_CLIENT_SECRET=...
```

With this configuration the server offers only the read-only tools. To also offer commands, set [`--mcp-read-only=false`](server-configuration.md#mcp-read-only).

To disable the MCP server, set `mcp-enabled` to `false` or remove it, and restart. Tokens stop working immediately.

## Connecting a client

For clients supporting [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization), add the endpoint without a token or header. With Claude Code:

```bash
claude mcp add --transport http atlantis https://atlantis.example.com/api/mcp
```

On first use, follow the client's login prompt. Atlantis shows the registered client name and callback address before continuing to GitHub. Approve only connections you started. After the GitHub login, the browser returns to your client; no token copying is needed.

OAuth access tokens last [`--mcp-access-token-ttl-hours`](server-configuration.md#mcp-access-token-ttl-hours) (default `1`). Refresh tokens rotate on every use and have an absolute lifetime of [`--mcp-refresh-token-ttl-hours`](server-configuration.md#mcp-refresh-token-ttl-hours) (default `720`, or 30 days) from the initial authorization. Rotation does not extend that lifetime. Sign in again after expiry or a server restart.

Set `--atlantis-url` to the externally reachable HTTPS URL. HTTP is accepted only for loopback development. A reverse proxy must forward the OAuth paths and origin-root `/.well-known/` discovery paths as well as `/api/mcp` and `/auth/github/`. If the external URL has a path prefix, forward the corresponding path-qualified discovery URLs too.

### OAuth endpoints

These endpoints exist only when the MCP experiment and `mcp-enabled` are both enabled:

| Path | Method | Purpose |
| --- | --- | --- |
| `/.well-known/oauth-protected-resource` | GET | MCP resource and authorization server discovery |
| `/.well-known/oauth-protected-resource/api/mcp` | GET | Resource-specific discovery; includes the external base path before `/api/mcp` when configured |
| `/.well-known/oauth-authorization-server` | GET | OAuth server metadata; also available with the external base path appended |
| `/oauth/register` | POST | Dynamic registration of public clients |
| `/oauth/authorize` | GET, POST | PKCE validation, client consent, and GitHub login |
| `/oauth/token` | POST | Authorization code exchange and refresh token rotation |
| `/auth/github/login` | GET | Manual personal token login |
| `/auth/github/callback` | GET | Shared GitHub login callback |

Registration accepts up to four redirect URIs, each at most 512 bytes, and a client name of at most 128 bytes. The encoded client identifier is limited to 4 KiB, and request bodies to 16 KiB. Redirects must use HTTPS or HTTP on `127.0.0.1`, `localhost`, or `[::1]` with an explicit port. Loopback clients may change only the port during authorization. Authorization requires S256 PKCE, and codes expire after 60 seconds and can be exchanged once. Token exchange requires the exact redirect URI used for authorization.

Atlantis supports public clients (`token_endpoint_auth_method=none`) through dynamic registration. It does not support client ID metadata documents, confidential client authentication, custom URI schemes, or OAuth scopes. Repository permissions continue to determine access on each call. A supplied `resource` must identify this server's MCP URL; older clients may omit it, but every OAuth token is still bound to that URL.

## Getting a manual token

Open `<atlantis-url>/auth/github/login` in a browser. After the GitHub login, Atlantis shows the token once, together with the endpoint URL.

Add the server to your MCP client. With Claude Code:

```bash
claude mcp add --transport http atlantis https://atlantis.example.com/api/mcp \
  --header "Authorization: Bearer <token>"
```

A token is valid for [`--mcp-token-ttl-hours`](server-configuration.md#mcp-token-ttl-hours), 168 hours by default. Log in again to get a new one.

## Tools

| Tool | Purpose | Needs |
| --- | --- | --- |
| `atlantis_whoami` | Show the token's user and expiry | A valid token |
| `atlantis_pull_status` | Head commit, project statuses, jobs, and locks of a pull request | Read permission |
| `atlantis_job_output` | Terminal output of one plan or apply job | Read permission |
| `atlantis_list_locks` | Locks held in a repository | Read permission |
| `atlantis_plan` | Run `atlantis plan` for one project or all of them | Write permission, `--mcp-read-only=false` |
| `atlantis_apply` | Run `atlantis apply` | Write permission, `--mcp-read-only=false` |
| `atlantis_unlock` | Run `atlantis unlock`, discarding plans and locks | Write permission, `--mcp-read-only=false` |

`atlantis_apply` requires the full head commit SHA of the pull request that the plan was reviewed for. Atlantis refuses the apply when the pull request has moved since.

Commands can take minutes. A tool call returns after at most 50 seconds. When the result reports a running command, the assistant calls `atlantis_pull_status` with `wait_seconds` until it has finished. Only one MCP command runs on a pull request at a time.

When Atlantis refuses a command, for example because of the team allowlist or an unmet apply requirement, it explains why in a pull request comment, as it does for comment commands. The tool result reports that the command finished without starting a job.

## Working without autoplan

When an assistant drives a pull request, autoplan on every push is usually unwanted. Set [`--disable-autoplan-label`](server-configuration.md#disable-autoplan-label) and let the assistant open its pull requests with that label. It then plans explicitly with `atlantis_plan`.

## Security

Enabling the MCP server adds an authenticated endpoint that can run Terraform. Consider the following before enabling it, and before setting `--mcp-read-only=false`.

- **The signing secret can impersonate anyone.** Whoever knows `mcp-token-secret` can create a valid token for any user. Store it like your other Atlantis secrets. Changing it revokes every token.
- **Tokens are bearer credentials.** A token lets its holder act as the user until it expires, without a second factor. Access and personal tokens cannot be revoked individually. Reusing a rotated refresh token invalidates its whole refresh family. Keep access token lifetimes short. Removing a user's repository or team access takes effect immediately, because Atlantis checks both on every call.
- **Plan output is untrusted input to the assistant.** It is produced by code in the pull request. A pull request can contain text that tries to instruct the assistant, for example to apply. The required head SHA, the unchanged apply requirements and your MCP client's confirmation of write tools limit this; they do not remove it. Do not let an assistant apply pull requests from authors you do not trust.
- **Restrict network access.** The endpoint is served on the Atlantis port under `/api/mcp`, which web basic auth does not cover. Expose it only where your users are, not to the whole internet.
- **OAuth discovery, registration, token exchange and the login pages bypass web basic auth.** Anyone who can reach `/auth/github/login` can obtain a token for their own GitHub account. Such a token is useless without permission on a repository in the [repo allowlist](server-configuration.md#repo-allowlist).

## Limitations

- GitHub only.
- OAuth requires a **single Atlantis instance**. Pending logins, issued codes and refresh families are held in bounded memory (up to 10,000 of each), with expired entries removed on use. Restarting invalidates them; clients must log in again. Access and personal tokens remain valid until expiry or signing-secret rotation. Multiple replicas cannot safely share these OAuth flows without shared replay and refresh state.
- Access and personal tokens cannot be revoked individually. Rotating the signing secret also invalidates stateless client registrations; clients must register again.
- Job output is kept in memory. It is unavailable after a restart, after the pull request is closed, and when Terraform Cloud remote execution is used.
- The reason for a refused command is available in the pull request comment, not in the tool result.
- The tools cover `plan`, `apply` and `unlock`. `import`, `state` and `approve_policies` are available through comments only.
