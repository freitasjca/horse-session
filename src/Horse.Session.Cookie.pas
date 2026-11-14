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
//  Cookie value format:  <session-id>.<base64url(HMAC-SHA256(key, id))>
//  The LAST dot separates id and signature, so an id may contain dots.
//  Issue the value with TCookieResolver.PackSessionId when the session is
//  created; expiry comes from the store record (ExpiresAt), not the cookie.
//
//  Reason codes: malformed-session-cookie, invalid-cookie-signature,
//  session-not-found-or-expired. A request without the cookie falls through
//  with an empty reason.
//
//  The signing key must be at least HORSE_SESSION_MIN_HMAC_KEY_BYTES (32)
//  bytes; a shorter one raises EHorseSessionConfig.
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
    class function CheckedKey(const ASigningKey: string): TBytes; static;
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
    /// Validates a bare cookie value (what PackSessionId returned).
    /// TryResolve calls this; it is public so a value can be checked
    /// without an HTTP request.
    function TryResolveCookieValue(const ACookieValue: string;
                                   out APrincipal: TPrincipal;
                                   out AReason: string): Boolean;
    function Name: string;
    class function New(const AStore: ISessionStore;
                       const ASigningKey: string;
                       const ACookieName: string = 'horse_session'): IPrincipalResolver;
    /// The value to put in Set-Cookie for ASessionId: the id plus its
    /// signature under ASigningKey.
    class function PackSessionId(const ASessionId: string;
                                 const ASigningKey: string): string;
  end;

const
  /// Cookie values longer than this are refused before any decoding.
  SESSION_COOKIE_MAX_CHARS = 4096;

/// Finds cookie AName in a Cookie request header ("a=1; b=2"). Names are
/// case-sensitive; surrounding double quotes on the value are removed.
function ExtractCookieValue(const ACookieHeader, AName: string;
                            out AValue: string): Boolean;

implementation

uses
  Horse.Session.Crypto;

function ExtractCookieValue(const ACookieHeader, AName: string;
                            out AValue: string): Boolean;
var
  LPos, LLen, LStart, LEq: Integer;
  LPair: string;
begin
  AValue := '';
  Result := False;
  if AName = '' then
    Exit;
  LLen := Length(ACookieHeader);
  LPos := 1;
  while LPos <= LLen do
  begin
    LStart := LPos;
    while (LPos <= LLen) and (ACookieHeader[LPos] <> ';') do
      Inc(LPos);
    LPair := Trim(Copy(ACookieHeader, LStart, LPos - LStart));
    Inc(LPos); // step over the ';'
    LEq := Pos('=', LPair);
    if (LEq > 1) and (Trim(Copy(LPair, 1, LEq - 1)) = AName) then
    begin
      AValue := Trim(Copy(LPair, LEq + 1, MaxInt));
      if (Length(AValue) >= 2) and (AValue[1] = '"') and
         (AValue[Length(AValue)] = '"') then
        AValue := Copy(AValue, 2, Length(AValue) - 2);
      Exit(True);
    end;
  end;
end;

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
  FSigningKey := CheckedKey(ASigningKey);
end;

class function TCookieResolver.CheckedKey(const ASigningKey: string): TBytes;
begin
  Result := Utf8BytesOf(ASigningKey);
  if Length(Result) < HORSE_SESSION_MIN_HMAC_KEY_BYTES then
    raise EHorseSessionConfig.CreateFmt(
      'Session cookie signing key must be at least %d bytes (got %d)',
      [HORSE_SESSION_MIN_HMAC_KEY_BYTES, Length(Result)]);
end;

class function TCookieResolver.PackSessionId(const ASessionId: string;
                                             const ASigningKey: string): string;
begin
  if ASessionId = '' then
    raise EHorseSessionConfig.Create('Session id must not be empty');
  Result := ASessionId + '.' +
            Base64UrlEncode(HmacSha256(CheckedKey(ASigningKey),
                                       Utf8BytesOf(ASessionId)));
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
var
  LDot, I: Integer;
  LId: string;
  LSignature: TBytes;
begin
  ASessionId := '';
  AReason := 'malformed-session-cookie';
  Result := False;

  if Length(ACookieValue) > SESSION_COOKIE_MAX_CHARS then
    Exit;

  LDot := 0;
  for I := Length(ACookieValue) downto 1 do
    if ACookieValue[I] = '.' then
    begin
      LDot := I;
      Break;
    end;
  if (LDot < 2) or (LDot = Length(ACookieValue)) then
    Exit;

  LId := Copy(ACookieValue, 1, LDot - 1);
  if not Base64UrlDecode(Copy(ACookieValue, LDot + 1, MaxInt), LSignature) then
    Exit;
  if Length(LSignature) <> 32 then
    Exit;

  if not ConstantTimeBytesEqual(HmacSha256(FSigningKey, Utf8BytesOf(LId)),
                                LSignature) then
  begin
    AReason := 'invalid-cookie-signature';
    Exit;
  end;

  ASessionId := LId;
  AReason := '';
  Result := True;
end;

function TCookieResolver.TryResolveCookieValue(const ACookieValue: string;
                                               out APrincipal: TPrincipal;
                                               out AReason: string): Boolean;
var
  LSessionId: string;
  LSession: TSessionRecord;
begin
  APrincipal := nil;
  AReason := '';
  Result := False;

  if not UnpackSessionId(ACookieValue, LSessionId, AReason) then
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

function TCookieResolver.TryResolve(const AReq: THorseRequest;
                                    out APrincipal: TPrincipal;
                                    out AReason: string): Boolean;
var
  LCookieValue: string;
begin
  APrincipal := nil;
  AReason := '';
  Result := False;

  // The Cookie header is parsed here rather than through Req.Cookie so the
  // behaviour is the same on every provider.
  if not ExtractCookieValue(AReq.Headers['Cookie'], FCookieName, LCookieValue) then
    Exit; // no session cookie on this request; fall through

  Result := TryResolveCookieValue(LCookieValue, APrincipal, AReason);
end;

end.
