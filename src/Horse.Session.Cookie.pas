unit Horse.Session.Cookie;

{$IF DEFINED(FPC)}{$MODE DELPHI}{$H+}{$ENDIF}

// =============================================================================
//  horse-session -- cookie-session resolver and session-store contract
//  -----------------------------------------------------------------------------
//  Reads a signed cookie value, looks up the matching session through
//  ISessionStore, and constructs a TPrincipal from the stored record.
//
//  The cookie carries an opaque session id plus a short HMAC for tamper
//  detection. The id is then looked up in ISessionStore -- the cookie is
//  NOT self-describing (JWT-style); keeping the server-side store means
//  revocation is immediate (delete from store).
//
//  SCAFFOLD NOTE: signing and TTL are TODO. TryResolve returns False with
//  AReason='scaffold-cookie-signing-stub' until the HMAC primitive is
//  shared with Horse.Session.Jwt. See that unit's VerifySignature TODO.
// =============================================================================

interface

uses
{$IF DEFINED(FPC)}
  SysUtils,
  Classes,
  SyncObjs,
  Generics.Collections,
{$ELSE}
  System.SysUtils,
  System.Classes,
  System.SyncObjs,
  System.Generics.Collections,
{$IFEND}
  Horse.Request,
  Horse.Session.Types,
  Horse.Session.Resolver;

type
  /// Session record keyed by the opaque id stored in the cookie.
  TSessionRecord = record
    SessionId: string;      // opaque; matches cookie id
    UserId: string;
    TenantId: string;
    Roles: TArray<string>;
    Scopes: TArray<string>;
    IssuedAt: TDateTime;
    ExpiresAt: TDateTime;   // zero = no TTL
  end;

  /// Pluggable session-backing store. Implementations MUST be safe for
  /// concurrent lookups + writes from arbitrary threads.
  ISessionStore = interface
    ['{5E9A1C7F-8D40-4A3B-B82E-9F7C4D6A1E80}']
    function TryLookup(const ASessionId: string;
                      out ARecord: TSessionRecord): Boolean;
    procedure Upsert(const ARecord: TSessionRecord);
    function Revoke(const ASessionId: string): Boolean;
    procedure Clear;
  end;

  /// In-memory session store. TTL enforced on lookup (expired entries
  /// return False and are removed). Suitable for dev / single-process
  /// deployments only.
  TMemorySessionStore = class(TInterfacedObject, ISessionStore)
  strict private
    FLock: TCriticalSection;
    FMap: TDictionary<string, TSessionRecord>;
  public
    constructor Create;
    destructor Destroy; override;
    function TryLookup(const ASessionId: string;
                      out ARecord: TSessionRecord): Boolean;
    procedure Upsert(const ARecord: TSessionRecord);
    function Revoke(const ASessionId: string): Boolean;
    procedure Clear;
  end;

  TCookieResolver = class(TInterfacedObject, IPrincipalResolver)
  strict private
    FStore: ISessionStore;
    FCookieName: string;
    FSigningKey: TBytes;
    function UnpackSessionId(const ACookieValue: string;
                             out ASessionId: string;
                             out AReason: string): Boolean;
  public
    constructor Create(const AStore: ISessionStore;
                       const ACookieName: string;
                       const ASigningKey: string);
    function TryResolve(const AReq: THorseRequest;
                       out APrincipal: TPrincipal;
                       out AReason: string): Boolean;
    function Name: string;
    class function New(const AStore: ISessionStore;
                       const ASigningKey: string;
                       const ACookieName: string = 'horse_session'): IPrincipalResolver;
  end;

implementation

{ TMemorySessionStore }

constructor TMemorySessionStore.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FMap := TDictionary<string, TSessionRecord>.Create;
end;

destructor TMemorySessionStore.Destroy;
begin
  FMap.Free;
  FLock.Free;
  inherited Destroy;
end;

function TMemorySessionStore.TryLookup(const ASessionId: string;
                                       out ARecord: TSessionRecord): Boolean;
begin
  FLock.Enter;
  try
    Result := FMap.TryGetValue(ASessionId, ARecord);
    if Result and (ARecord.ExpiresAt > 0) and (Now > ARecord.ExpiresAt) then
    begin
      FMap.Remove(ASessionId);
      Result := False;
    end;
  finally
    FLock.Leave;
  end;
end;

procedure TMemorySessionStore.Upsert(const ARecord: TSessionRecord);
begin
  FLock.Enter;
  try
    FMap.AddOrSetValue(ARecord.SessionId, ARecord);
  finally
    FLock.Leave;
  end;
end;

function TMemorySessionStore.Revoke(const ASessionId: string): Boolean;
begin
  FLock.Enter;
  try
    Result := FMap.ContainsKey(ASessionId);
    FMap.Remove(ASessionId);
  finally
    FLock.Leave;
  end;
end;

procedure TMemorySessionStore.Clear;
begin
  FLock.Enter;
  try
    FMap.Clear;
  finally
    FLock.Leave;
  end;
end;

{ TCookieResolver }

constructor TCookieResolver.Create(const AStore: ISessionStore;
                                   const ACookieName: string;
                                   const ASigningKey: string);
begin
  inherited Create;
  FStore := AStore;
  FCookieName := ACookieName;
  FSigningKey := TEncoding.UTF8.GetBytes(ASigningKey);
end;

class function TCookieResolver.New(const AStore: ISessionStore;
                                   const ASigningKey: string;
                                   const ACookieName: string): IPrincipalResolver;
begin
  Result := TCookieResolver.Create(AStore, ACookieName, ASigningKey);
end;

function TCookieResolver.Name: string;
begin
  Result := 'cookie';
end;

function TCookieResolver.UnpackSessionId(const ACookieValue: string;
                                         out ASessionId: string;
                                         out AReason: string): Boolean;
begin
  // TODO: split <id>.<hmac>, verify HMAC with FSigningKey (shared primitive
  // with Horse.Session.Jwt.VerifySignature), set ASessionId on success.
  ASessionId := '';
  AReason := 'scaffold-cookie-signing-stub';
  Result := False;
end;

function TCookieResolver.TryResolve(const AReq: THorseRequest;
                                    out APrincipal: TPrincipal;
                                    out AReason: string): Boolean;
var
  LCookieValue: string;
  LSessionId: string;
  LSession: TSessionRecord;
begin
  APrincipal := nil;
  AReason := '';
  Result := False;

  // TODO: parse Cookie header for FCookieName. Horse exposes
  // AReq.Cookie[FCookieName] via the RawWebRequest; keep the parsing in a
  // dedicated helper to isolate transport differences.
  LCookieValue := AReq.Headers['Cookie'];
  if LCookieValue = '' then
    Exit;

  if not UnpackSessionId(LCookieValue, LSessionId, AReason) then
    Exit;

  if not FStore.TryLookup(LSessionId, LSession) then
  begin
    AReason := 'session-not-found-or-expired';
    Exit;
  end;

  APrincipal := TPrincipal.Create(
    LSession.UserId,
    LSession.TenantId,
    LSession.Roles,
    LSession.Scopes,
    nil,
    True);
  Result := True;
end;

end.
