unit Horse.Session.Middleware;

{$IF DEFINED(FPC)}{$MODE DELPHI}{$H+}{$ENDIF}

// =============================================================================
//  horse-session -- main middleware facade
//  -----------------------------------------------------------------------------
//  Runs the configured IPrincipalResolver chain (first success wins) and
//  attaches the resulting TPrincipal to the request (SetPrincipal in
//  Horse.Session.Types). Downstream middleware (THorseAuthorize) and
//  consumer packages (horse-ai-conversations) read it with PrincipalOf.
//  The request owns the principal and Horse frees it at request end.
//
//  This unit is NOT called Horse.Session: Horse core already has a unit
//  with that name.
//
//  Behaviour:
//    - On success: write an authenticated TPrincipal, audit as
//      'authentication.succeeded', call Next.
//    - On resolver recognised request but rejected credentials: write an
//      anonymous TPrincipal, audit as 'authentication.failed' with the
//      resolver's AReason code, call Next. (Routes downstream can still
//      choose to reject via THorseAuthorize.RequireAuthenticated.)
//    - On no resolver recognising the request: write an anonymous
//      TPrincipal, emit no audit event, call Next.
//
//  Fail-open vs fail-closed audit policy:
//    - Default: an exception raised by IAuthAuditSink.RecordEvent is
//      swallowed (matches AddOnTelemetry convention).
//    - FailClosed=True: a raising sink aborts the request with 500.
//
//  FPC NOTE: same plain-procedure + globals pattern as
//  horse-request-guard. The config is process-wide: a second New(AConfig)
//  replaces the first.
// =============================================================================

interface

uses
{$IF DEFINED(FPC)}
  SysUtils,
  Classes,
  Generics.Collections,
{$ELSE}
  System.SysUtils,
  System.Classes,
  System.Generics.Collections,
{$IFEND}
  Horse.Request,
  Horse.Response,
  Horse.Callback,
  Horse.Proc,
  Horse.Session.Types,
  Horse.Session.Audit,
  Horse.Session.Resolver;

type
  THorseSessionConfig = record
    /// Ordered resolver chain. First success wins. An empty chain means
    /// every request is anonymous.
    Resolvers: TArray<IPrincipalResolver>;
    /// Where authentication / authorization events go. Default is a
    /// TNullAuthAuditSink (discards silently).
    AuditSink: IAuthAuditSink;
    /// When True, an exception raised by AuditSink.RecordEvent aborts the
    /// request with 500. Default False (telemetry convention: audit
    /// failures never break the response path).
    FailClosed: Boolean;
    class function Default: THorseSessionConfig; static;
  end;

  THorseSession = class
  public
    class function New: THorseCallback; overload;
    class function New(const AConfig: THorseSessionConfig): THorseCallback; overload;
  end;

/// Sends AEvent to the sink configured through THorseSession.New, honouring
/// FailClosed. A no-op before the middleware is installed. Used by
/// Horse.Session.Authorize so authorization decisions reach the same sink.
procedure HorseSessionAudit(const AEvent: TAuthAuditEvent);

implementation

var
  GConfig: THorseSessionConfig;
  GInstalled: Boolean;

{ THorseSessionConfig }

class function THorseSessionConfig.Default: THorseSessionConfig;
begin
  SetLength(Result.Resolvers, 0);
  Result.AuditSink := TNullAuthAuditSink.Create;
  Result.FailClosed := False;
end;

procedure HorseSessionAudit(const AEvent: TAuthAuditEvent);
begin
  if (not GInstalled) or (GConfig.AuditSink = nil) then
    Exit;
  try
    GConfig.AuditSink.RecordEvent(AEvent);
  except
    if GConfig.FailClosed then
      raise;
    // fail-open: swallow
  end;
end;

procedure SessionProc(AReq: THorseRequest; ARes: THorseResponse; ANext: TNextProc);
var
  LResolver: IPrincipalResolver;
  LPrincipal: TPrincipal;
  LReason: string;
  LRecognised: Boolean;
  LAccepted: Boolean;
  LCorrelationId: string;
  LResolverName: string;
begin
  if not GInstalled then
  begin
    ANext;
    Exit;
  end;

  LPrincipal := nil;
  LReason := '';
  LRecognised := False;
  LAccepted := False;

  LResolverName := '';

  for LResolver in GConfig.Resolvers do
  begin
    if LResolver = nil then
      Continue;
    if LResolver.TryResolve(AReq, LPrincipal, LReason) and
       (LPrincipal <> nil) and LPrincipal.IsAuthenticated then
    begin
      LAccepted := True;
      LResolverName := LResolver.Name;
      Break;
    end;
    // Not accepted: whatever the resolver left behind is never trusted.
    FreeAndNil(LPrincipal);
    if LReason <> '' then
    begin
      LRecognised := True;
      Break; // resolver recognised AND rejected -> stop the chain
    end;
  end;

  if LPrincipal = nil then
    LPrincipal := TPrincipal.CreateAnonymous;

  // From here the request owns LPrincipal; Horse frees it at request end.
  SetPrincipal(AReq, LPrincipal);

  LCorrelationId := AReq.Headers['X-Request-ID'];

  if LAccepted then
    HorseSessionAudit(MakeAuthEvent('authentication.succeeded',
                            LPrincipal.TenantId, LPrincipal.UserId,
                            'route', AReq.PathInfo,
                            'succeeded', LResolverName, LCorrelationId))
  else if LRecognised then
    HorseSessionAudit(MakeAuthEvent('authentication.failed',
                            '', '',
                            'route', AReq.PathInfo,
                            'failed', LReason, LCorrelationId));

  ANext;
end;

{ THorseSession }

class function THorseSession.New: THorseCallback;
begin
  Result := New(THorseSessionConfig.Default);
end;

class function THorseSession.New(const AConfig: THorseSessionConfig): THorseCallback;
begin
  GConfig := AConfig;
  GInstalled := True;
  Result := SessionProc;
end;

initialization
  GInstalled := False;

end.
