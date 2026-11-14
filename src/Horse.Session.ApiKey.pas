unit Horse.Session.ApiKey;

{$IF DEFINED(FPC)}{$MODE DELPHI}{$H+}{$ENDIF}

// =============================================================================
//  horse-session -- API-key resolver
//  -----------------------------------------------------------------------------
//  Reads an API key from a configurable header (default X-API-Key) or query
//  parameter, looks the key up through IApiKeyStore, and constructs a
//  TPrincipal from the matching record. Comparison is constant-time to avoid
//  timing side-channels.
//
//  IApiKeyStore is pluggable; TMemoryApiKeyStore is the v1 default. Durable
//  stores (Redis, FireDAC) ship as sibling packages.
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
  /// API-key -> principal mapping record. Returned from IApiKeyStore.Lookup.
  /// The store owns no instance here -- it populates and returns by value.
  TApiKeyRecord = record
    UserId: string;
    TenantId: string;
    Roles: TArray<string>;
    Scopes: TArray<string>;
  end;

  /// Pluggable store. Implementations MUST be safe for concurrent lookups
  /// from arbitrary threads. Lookup MUST be constant-time with respect to
  /// AProvidedKey (or wrap a map lookup with ConstantTimeEquals against the
  /// candidate's stored hash).
  IApiKeyStore = interface
    ['{4A8F7C2E-5B9D-4612-9A4E-3C6F8D1B7E59}']
    function Lookup(const AProvidedKey: string;
                   out ARecord: TApiKeyRecord): Boolean;
  end;

  /// In-memory map keyed on the raw API-key string. Suitable for development
  /// and small single-process deployments only. Production uses a durable
  /// sibling store (horse-session-redis, horse-session-firedac).
  TMemoryApiKeyStore = class(TInterfacedObject, IApiKeyStore)
  strict private
    FLock: TCriticalSection;
    FMap: TDictionary<string, TApiKeyRecord>;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Add(const AKey: string; const ARecord: TApiKeyRecord);
    function Lookup(const AProvidedKey: string;
                   out ARecord: TApiKeyRecord): Boolean;
  end;

  TApiKeyResolver = class(TInterfacedObject, IPrincipalResolver)
  strict private
    FStore: IApiKeyStore;
    FHeaderName: string;
    FQueryParamName: string;
  public
    constructor Create(const AStore: IApiKeyStore;
                       const AHeaderName: string = 'X-API-Key';
                       const AQueryParamName: string = '');
    function TryResolve(const AReq: THorseRequest;
                       out APrincipal: TPrincipal;
                       out AReason: string): Boolean;
    function Name: string;
    class function New(const AStore: IApiKeyStore): IPrincipalResolver;
  end;

/// Constant-time string comparison. Returns True iff both strings are
/// byte-equal; timing is independent of common-prefix length.
function ConstantTimeEquals(const A, B: string): Boolean;

implementation

function ConstantTimeEquals(const A, B: string): Boolean;
var
  I, LDiff, LLen: Integer;
begin
  // Different lengths -> False, but still run through equal chars to keep
  // timing proportional to Length(A) rather than branching early.
  LLen := Length(A);
  LDiff := Length(A) xor Length(B);
  if (Length(B) < LLen) then
    LLen := Length(B);
  for I := 1 to LLen do
    LDiff := LDiff or (Ord(A[I]) xor Ord(B[I]));
  Result := LDiff = 0;
end;

{ TMemoryApiKeyStore }

constructor TMemoryApiKeyStore.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FMap := TDictionary<string, TApiKeyRecord>.Create;
end;

destructor TMemoryApiKeyStore.Destroy;
begin
  FMap.Free;
  FLock.Free;
  inherited Destroy;
end;

procedure TMemoryApiKeyStore.Add(const AKey: string; const ARecord: TApiKeyRecord);
begin
  FLock.Enter;
  try
    FMap.AddOrSetValue(AKey, ARecord);
  finally
    FLock.Leave;
  end;
end;

function TMemoryApiKeyStore.Lookup(const AProvidedKey: string;
                                   out ARecord: TApiKeyRecord): Boolean;
var
  LKey: string;
  LFound: TApiKeyRecord;
  LAny: Boolean;
begin
  // Iterate every entry and apply ConstantTimeEquals to every key so lookup
  // time does not leak which keys are stored. For large deployments the
  // right answer is a store that keeps a hash of the key -- scaffold
  // in-memory impl is intentionally simple.
  Result := False;
  LAny := False;
  FLock.Enter;
  try
    for LKey in FMap.Keys do
    begin
      if ConstantTimeEquals(LKey, AProvidedKey) then
      begin
        LFound := FMap[LKey];
        LAny := True;
      end;
    end;
    if LAny then
    begin
      ARecord := LFound;
      Result := True;
    end;
  finally
    FLock.Leave;
  end;
end;

{ TApiKeyResolver }

constructor TApiKeyResolver.Create(const AStore: IApiKeyStore;
                                   const AHeaderName: string;
                                   const AQueryParamName: string);
begin
  inherited Create;
  FStore := AStore;
  FHeaderName := AHeaderName;
  FQueryParamName := AQueryParamName;
end;

class function TApiKeyResolver.New(const AStore: IApiKeyStore): IPrincipalResolver;
begin
  Result := TApiKeyResolver.Create(AStore);
end;

function TApiKeyResolver.Name: string;
begin
  Result := 'api-key';
end;

function TApiKeyResolver.TryResolve(const AReq: THorseRequest;
                                    out APrincipal: TPrincipal;
                                    out AReason: string): Boolean;
var
  LProvided: string;
  LRecord: TApiKeyRecord;
begin
  APrincipal := nil;
  AReason := '';
  Result := False;
  LProvided := '';

  if FHeaderName <> '' then
    LProvided := AReq.Headers[FHeaderName];

  if (LProvided = '') and (FQueryParamName <> '') then
    LProvided := AReq.Query[FQueryParamName];

  if LProvided = '' then
    Exit; // no API-key on this request; fall through

  if not FStore.Lookup(LProvided, LRecord) then
  begin
    AReason := 'invalid-api-key';
    Exit;
  end;

  APrincipal := TPrincipal.Create(
    LRecord.UserId,
    LRecord.TenantId,
    LRecord.Roles,
    LRecord.Scopes,
    nil,
    True);
  Result := True;
end;

end.
