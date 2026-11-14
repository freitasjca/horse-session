# horse-session

Authentication identity middleware for the [Horse](https://github.com/HashLoad/horse) web framework.

Status: **v0.1.0-alpha.1** — scaffold. See `docs/horse-session-decision.md` in the workspace for the full ADR.

## What it does

- Extracts a `TPrincipal` (user id, tenant id, roles, scopes, claims) from every HTTP request via a chain of pluggable `IPrincipalResolver` implementations.
- Writes the principal to `Req.Session[HORSE_SESSION_PRINCIPAL_KEY]`. Downstream middleware (including `horse-ai-conversations`) reads from there.
- Emits security events through `IAuthAuditSink` with a stable, backward-compatible `TAuthAuditEvent` record shared across the Horse ecosystem.
- Ships basic role / scope authorization helpers (`THorseAuthorize.RequireRole`, `.RequireScope`, `.RequireAuthenticated`).

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
  Horse,
  Horse.Session,
  Horse.Session.Types,
  Horse.Session.Jwt,
  Horse.Session.ApiKey,
  Horse.Session.Authorize;

var
  LConfig: THorseSessionConfig;
begin
  LConfig := THorseSessionConfig.Default;
  LConfig.Resolvers := [
    TJwtHS256Resolver.New('my-shared-secret'),
    TApiKeyResolver.New(TApiKeyMap.Create(['alice-key', 'bob-key']))
  ];

  THorse.Use(THorseSession.New(LConfig));
  THorse.Use(THorseAuthorize.RequireAuthenticated);

  THorse.Get('/admin',
    THorseAuthorize.RequireRole('admin'),
    procedure(Req: THorseRequest; Res: THorseResponse)
    var
      LPrincipal: TPrincipal;
    begin
      LPrincipal := TPrincipal(Req.Session[HORSE_SESSION_PRINCIPAL_KEY]);
      Res.Send('Hello, ' + LPrincipal.UserId);
    end);

  THorse.Listen(9000);
end.
```

## Audit event schema (ecosystem contract)

`TAuthAuditEvent` + `IAuthAuditSink` live in `Horse.Session.Audit` and are **stable and backward-compatible**. Sibling packages (`horse-ai-conversations`, future audit consumers) reuse them unchanged. New event kinds appear as new `Action` strings, never as new record fields.

Hard constraints: audit records **never** contain credentials (keys, JWTs, cookie values, passwords), **never** contain AI prompts or model output, and `Reason` carries a short error code — never a raw exception message.

## Provider compatibility

| Provider      | HTTP auth | mTLS |
|---------------|-----------|------|
| CrossSocket   | ✓         | ✓ (via `Horse.Session.CrossSocket`) |
| nghttp2       | ✓         | — (ships with provider repo in later release) |
| mORMot        | ✓         | — |
| ICS           | ✓         | — |
| Indy          | ✓         | — |
| Apache / ISAPI / CGI | ✓  | n/a (upstream handles it) |

## See also

- `docs/horse-session-decision.md` — ADR for the full rationale.
- `docs/horse-ai-conversations-decision.md` — the consumer that uses this package's principal to own AI streams.
- `docs/middleware.md` — framework rules every Horse middleware honours.
