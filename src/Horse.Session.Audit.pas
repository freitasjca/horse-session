unit Horse.Session.Audit;

{$IF DEFINED(FPC)}{$MODE DELPHI}{$H+}{$ENDIF}

// =============================================================================
//  horse-session -- audit event schema (ECOSYSTEM CONTRACT)
//  -----------------------------------------------------------------------------
//  TAuthAuditEvent and IAuthAuditSink are the stable security-event surface
//  that every Horse ecosystem package reuses unchanged. horse-ai-conversations
//  does NOT declare its own audit interface or record -- it consumes these and
//  reserves Action prefixes ('conversation.', 'stream.') in the shared
//  vocabulary.
//
//  Stability contract (see docs/horse-session-decision.md §Audit event schema):
//    - New event kinds appear as new Action strings, never as new fields.
//    - Sinks written against v1 keep working against vN.
//    - Hard content constraints: NEVER log credentials (API keys, JWTs,
//      cookie values, passwords, OAuth tokens), NEVER log prompts or model
//      output, Reason carries a short code -- never a raw exception message.
//
//  Action vocabulary (open set; v1 reserved prefixes):
//    authentication.{succeeded,failed}
//    authorization.{granted,denied}
//    session.{created,expired,revoked}
//    conversation.{created,accessed,access.denied,deleted}  <-- horse-ai-conversations
//    stream.{started,cancelled,cancel.denied}               <-- horse-ai-conversations
// =============================================================================

interface

uses
{$IF DEFINED(FPC)}
  SysUtils,
  DateUtils,
  Classes,
  SyncObjs;
{$ELSE}
  System.SysUtils,
  System.DateUtils,
  System.Classes,
  System.SyncObjs;
{$IFEND}

type
  /// Stable ecosystem record. Fields are backward-compatible; new event
  /// kinds appear as new Action strings, never as new fields.
  TAuthAuditEvent = record
    Timestamp: TDateTime;    // UTC
    TenantId: string;        // from authenticated principal; empty for anonymous
    PrincipalId: string;     // from authenticated principal; empty for anonymous
    Action: string;          // dotted verb (see vocabulary in unit header)
    ResourceType: string;    // e.g. 'route', 'conversation', 'stream'
    ResourceId: string;      // opaque; type-specific
    Outcome: string;         // 'granted' | 'denied' | 'succeeded' | 'failed'
    Reason: string;          // short error code; NEVER a raw exception message
    CorrelationId: string;   // request-level correlation id
  end;

  /// Stable ecosystem interface. Implementations MUST be safe for concurrent
  /// calls from arbitrary threads (HTTP providers dispatch from worker
  /// threads). RecordEvent MUST NOT raise under normal operation; see the
  /// fail-open / fail-closed policy below.
  IAuthAuditSink = interface
    ['{7F5C9A14-6D2B-4E89-B3AF-1C8E5F7A9D32}']
    procedure RecordEvent(const AEvent: TAuthAuditEvent);
  end;

  /// Default sink. Discards every event silently; production deployments
  /// install their own. Thread-safe by construction (no state).
  TNullAuthAuditSink = class(TInterfacedObject, IAuthAuditSink)
  public
    procedure RecordEvent(const AEvent: TAuthAuditEvent);
  end;

  /// Thread-safe in-memory capture sink. Intended for tests and development
  /// only -- never for production (unbounded growth). Returns a snapshot
  /// on read, never the underlying buffer.
  TMemoryAuthAuditSink = class(TInterfacedObject, IAuthAuditSink)
  strict private
    FLock: TCriticalSection;
    FEvents: TArray<TAuthAuditEvent>;
  public
    constructor Create;
    destructor Destroy; override;
    procedure RecordEvent(const AEvent: TAuthAuditEvent);
    function Snapshot: TArray<TAuthAuditEvent>;
    procedure Clear;
  end;

/// Build a TAuthAuditEvent with Timestamp = NowUTC and the given fields.
/// Use through THorseSession or the authorize helpers rather than
/// hand-constructing records.
function MakeAuthEvent(const AAction, ATenantId, APrincipalId,
                      AResourceType, AResourceId, AOutcome, AReason,
                      ACorrelationId: string): TAuthAuditEvent;

implementation

function MakeAuthEvent(const AAction, ATenantId, APrincipalId,
                      AResourceType, AResourceId, AOutcome, AReason,
                      ACorrelationId: string): TAuthAuditEvent;
begin
{$IF DEFINED(FPC)}
  Result.Timestamp := LocalTimeToUniversal(Now);
{$ELSE}
  Result.Timestamp := TTimeZone.Local.ToUniversalTime(Now);
{$IFEND}
  Result.TenantId := ATenantId;
  Result.PrincipalId := APrincipalId;
  Result.Action := AAction;
  Result.ResourceType := AResourceType;
  Result.ResourceId := AResourceId;
  Result.Outcome := AOutcome;
  Result.Reason := AReason;
  Result.CorrelationId := ACorrelationId;
end;

{ TNullAuthAuditSink }

procedure TNullAuthAuditSink.RecordEvent(const AEvent: TAuthAuditEvent);
begin
  // intentionally empty
end;

{ TMemoryAuthAuditSink }

constructor TMemoryAuthAuditSink.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  SetLength(FEvents, 0);
end;

destructor TMemoryAuthAuditSink.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

procedure TMemoryAuthAuditSink.RecordEvent(const AEvent: TAuthAuditEvent);
begin
  FLock.Enter;
  try
    SetLength(FEvents, Length(FEvents) + 1);
    FEvents[High(FEvents)] := AEvent;
  finally
    FLock.Leave;
  end;
end;

function TMemoryAuthAuditSink.Snapshot: TArray<TAuthAuditEvent>;
var
  I: Integer;
begin
  Result := nil;
  FLock.Enter;
  try
    SetLength(Result, Length(FEvents));
    for I := 0 to High(FEvents) do
      Result[I] := FEvents[I];
  finally
    FLock.Leave;
  end;
end;

procedure TMemoryAuthAuditSink.Clear;
begin
  FLock.Enter;
  try
    SetLength(FEvents, 0);
  finally
    FLock.Leave;
  end;
end;

end.
