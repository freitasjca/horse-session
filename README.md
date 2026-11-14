# horse-session

Authentication identity middleware for the [Horse](https://github.com/HashLoad/horse) web framework.

Status: **alpha**. JWT, API-key and cookie authentication and the authorization checks are implemented and tested; mTLS is not functional yet (see the provider table). See `docs/horse-session-decision.md` in the workspace for the full ADR.

## What it does

- Extracts a `TPrincipal` (user id, tenant id, roles, scopes, claims) from every HTTP request via a chain of pluggable `IPrincipalResolver` implementations.
- Attaches the principal to the request. Downstream code (including `horse-ai-conversations`) reads it with `PrincipalOf(Req)`.
- Emits security events through `IAuthAuditSink` with a stable, backward-compatible `TAuthAuditEvent` record shared across the Horse ecosystem.
- Ships basic role / scope authorization checks (`THorseAuthorize`, see Authorization below).

## Not in v1

- WebSocket upgrade authentication (HTTP only).
- RS256 / ES256 JWT (HS256 only; asymmetric algorithms ship as `horse-session-jwt-openssl` later).
- mTLS on providers other than CrossSocket (interface is defined; provider impls land in each provider repo).
- OAuth / OIDC redirect flow.
- Durable session stores (interface is defined; Redis / Postgres / FireDAC adapters ship as siblings).

## Install

```sh
boss install github.com/freitasjca/horse-session
```

## Quick start

```pascal
uses
  System.SysUtils,
  Horse,
  Horse.Session.Middleware,
  Horse.Session.Types,
  Horse.Session.Jwt,
  Horse.Session.ApiKey,
  Horse.Session.Authorize;

var
  LConfig: THorseSessionConfig;
  LKeys: TMemoryApiKeyStore;
  LKey: TApiKeyRecord;
begin
  LKeys := TMemoryApiKeyStore.Create;
  LKey := Default(TApiKeyRecord);
  LKey.UserId := 'svc-reports';
  LKey.TenantId := 'acme';
  LKeys.Add(GetEnvironmentVariable('REPORTS_API_KEY'), LKey);

  LConfig := THorseSessionConfig.Default;
  LConfig.Resolvers := [
    // the secret must be at least 32 bytes
    TJwtHS256Resolver.New(GetEnvironmentVariable('JWT_SECRET')),
    TApiKeyResolver.New(LKeys)
  ];

  THorse.Use(THorseSession.New(LConfig));
  THorse.Use(THorseAuthorize.RequireAuthenticated());

  THorse.Get('/admin',
    procedure(Req: THorseRequest; Res: THorseResponse)
    begin
      THorseAuthorize.DemandRole(Req, Res, 'admin');
      Res.Send('Hello, ' + PrincipalOf(Req).UserId);
    end);

  THorse.Listen(9000);
end.
```

The main unit is `Horse.Session.Middleware`, not `Horse.Session`: Horse itself already has a unit with that name.

## Reading the principal

The middleware attaches a `TPrincipal` to every request, authenticated or anonymous. Read it with `PrincipalOf(Req)` or `TryGetPrincipal(Req, LPrincipal)` from `Horse.Session.Types`. The request owns the principal and Horse frees it when the request ends, so never free it yourself.

## Authorization

| Call | Where | Refusal |
|------|-------|---------|
| `THorseAuthorize.RequireAuthenticated()` (keep the parentheses) | middleware, Delphi and FPC | 401 |
| `THorseAuthorize.DemandAuthenticated(Req, Res)` | inside a handler, Delphi and FPC | 401 |
| `THorseAuthorize.DemandRole(Req, Res, 'admin')` | inside a handler, Delphi and FPC | 401, or 403 without the role |
| `THorseAuthorize.DemandScope(Req, Res, 'write')` | inside a handler, Delphi and FPC | 401, or 403 without the scope |
| `THorseAuthorize.RequireRole('admin')` / `RequireScope('write')` | middleware, **Delphi only** | 401 / 403 |

`RequireRole` and `RequireScope` have to remember their argument for each route, which needs a closure. On FPC a Horse callback is a plain procedure and cannot hold one, so use `DemandRole` / `DemandScope` at the top of the handler there. A `Demand*` call that refuses sends the status and stops the handler.

Every refusal is audited as `authorization.denied` with reason `not-authenticated`, `missing-role` or `missing-scope`.

## JWT (HS256)

`TJwtHS256Resolver` reads `Authorization: Bearer <token>` and accepts a token only when all of these hold:

- the header `alg` is exactly `HS256` (so `none` and every other algorithm are refused);
- the HMAC-SHA256 signature matches, compared in constant time, before any claim is read;
- `exp` is present and in the future, and `nbf` (if present) has passed, each with 30 seconds of leeway by default;
- `iss` and `aud` match, when you pass an expected issuer or audience to `Create`;
- `sub` is a non-empty string.

Claim mapping: `sub` → `UserId`, `tenant` (or `tid`) → `TenantId`, `roles` → `Roles`, space-separated `scope` → `Scopes`; every top-level claim is also available through `Claims`.

The secret must be at least 32 bytes (RFC 7518 §3.2). A shorter one raises `EHorseSessionConfig` when the resolver is created. Set `RequireExp := False` only if you really issue tokens that never expire.

## Session cookie

`TCookieResolver` reads the cookie (default name `horse_session`) from the `Cookie` header. The value is `<session-id>.<signature>`, where the signature is HMAC-SHA256 of the id under your signing key (at least 32 bytes). The session itself lives in an `ISessionStore`, so deleting it there revokes it at once.

When you create a session, store the record and send the signed value yourself:

```pascal
LStore.Upsert(LSessionRecord);
Res.AddHeader('Set-Cookie',
  'horse_session=' + TCookieResolver.PackSessionId(LSessionRecord.SessionId, LSigningKey) +
  '; HttpOnly; Secure; SameSite=Lax; Path=/');
```

Generate the session id from a cryptographic random source; the package does not generate ids.

## Audit event schema (ecosystem contract)

`TAuthAuditEvent` + `IAuthAuditSink` live in `Horse.Session.Audit` and are **stable and backward-compatible**. Sibling packages (`horse-ai-conversations`, future audit consumers) reuse them unchanged. New event kinds appear as new `Action` strings, never as new record fields.

Hard constraints: audit records **never** contain credentials (keys, JWTs, cookie values, passwords), **never** contain AI prompts or model output, and `Reason` carries a short error code — never a raw exception message.

## Provider compatibility

| Provider      | HTTP auth | mTLS |
|---------------|-----------|------|
| CrossSocket   | ✓         | not yet: the contract and `TMTLSResolver` exist, the hook in the provider does not |
| nghttp2       | ✓         | — (ships with provider repo in later release) |
| mORMot        | ✓         | — |
| ICS           | ✓         | — |
| Indy          | ✓         | — |
| Apache / ISAPI / CGI | ✓  | n/a (upstream handles it) |

The HTTP auth column is by design: the package only uses Horse's request API, which every provider fills in. It is tested in-process (see `tests/`), not yet against a live server on each provider.

## See also

- `docs/horse-session-decision.md` — ADR for the full rationale.
- `docs/horse-ai-conversations-decision.md` — the consumer that uses this package's principal to own AI streams.
- `docs/middleware.md` — framework rules every Horse middleware honours.
