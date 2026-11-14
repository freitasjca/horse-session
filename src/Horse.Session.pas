unit Horse.Session;

{$IF DEFINED(FPC)}{$MODE DELPHI}{$H+}{$ENDIF}

// =============================================================================
//  horse-session -- main middleware facade
//  -----------------------------------------------------------------------------
//  Runs the configured IPrincipalResolver chain (first success wins) and
//  writes the resulting TPrincipal to Req.Session[HORSE_SESSION_PRINCIPAL_KEY].
//  Downstream middleware (THorseAuthorize.Require*) and consumer packages
//  (horse-ai-conversations) read from that key.
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
//  horse-request-guard / Horse.Session.Authorize. Process-wide config.
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

implementation

uses
  Horse.Exception.Interrupted;

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

procedure EmitAudit(const AEvent: TAuthAuditEvent);
begin
  if GConfig.AuditSink = nil then
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

  for LResolver in GConfig.Resolvers do
  begin
    if LResolver.TryResolve(AReq, LPrincipal, LReason) then
    begin
      LAccepted := True;
      Break;
    end;
    if LReason <> '' then
    begin
      LRecognised := True;
      Break; // resolver recognised AND rejected -> stop the chain
    end;
  end;

  if LPrincipal = nil then
    LPrincipal := TPrincipal.CreateAnonymous;

  AReq.Session.AddOrSetValue(HORSE_SESSION_PRINCIPAL_KEY, LPrincipal);
  // Note: TDictionary ownership of TObject values is the caller's concern.
  // Horse's Req.Session is a TDictionary<string,TObject>; the principal
  // will leak unless the app or middleware frees it. The horse-session
  // onResponse hook (TODO in v0.2) will free the principal at request end.

  // scaffold correlation id -- Horse exposes a request-id header convention
  // that varies by provider; a real implementation reads X-Request-ID.
  LCorrelationId := AReq.Headers['X-Request-ID'];

  if LAccepted then
    EmitAudit(MakeAuthEvent('authentication.succeeded',
                            LPrincipal.TenantId, LPrincipal.UserId,
                            'route', AReq.PathInfo,
                            'succeeded', LResolver.Name, LCorrelationId))
  else if LRecognised then
    EmitAudit(MakeAuthEvent('authentication.failed',
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
