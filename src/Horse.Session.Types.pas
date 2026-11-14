unit Horse.Session.Types;

{$IF DEFINED(FPC)}{$MODE DELPHI}{$H+}{$ENDIF}

// =============================================================================
//  horse-session -- shared data types and ecosystem constants
//  -----------------------------------------------------------------------------
//  TPrincipal is the identity contract every resolver populates and every
//  downstream consumer reads.
//
//  Where the principal lives: TPrincipal descends from Horse's TSession and
//  is stored in Req.Sessions under its own class (SetPrincipal). Horse owns
//  whatever is stored there and frees it when the request ends, so nobody
//  frees a principal obtained from a request. Sibling packages read it with
//  PrincipalOf / TryGetPrincipal, never through Req.Sessions directly.
//
//  Unit naming: Horse core already has a unit called Horse.Session (it
//  declares TSession). This package's units are all Horse.Session.<Name>;
//  the middleware is Horse.Session.Middleware.
//
//  Dual-compile notes (every unit compiles on Delphi 10.4+ and FPC 3.2.2+):
//    - Plain record with class-method Default factory, no generics in the
//      data layer. Generics.Collections is used only where a map is needed
//      (Claims).
//    - No globals, no class vars. This unit is pure declarations plus the
//      TPrincipal.Empty factory.
// =============================================================================

interface

uses
{$IF DEFINED(FPC)}
  SysUtils,
  Generics.Collections,
{$ELSE}
  System.SysUtils,
  System.Generics.Collections,
{$IFEND}
  Horse.Session,   // Horse core: TSession, THorseSessions
  Horse.Request;

type
  /// Claims bag -- opaque, string-to-string, extension point for anything
  /// the native TPrincipal fields don't cover.
  TClaims = TDictionary<string, string>;

  /// Authenticated principal. Immutable after the resolver chain completes:
  /// downstream middleware reads but never mutates it.
  TPrincipal = class(TSession)
  strict private
    FUserId: string;
    FTenantId: string;
    FRoles: TArray<string>;
    FScopes: TArray<string>;
    FClaims: TClaims;
    FIsAuthenticated: Boolean;
  public
    constructor Create(const AUserId, ATenantId: string;
                       const ARoles, AScopes: TArray<string>;
                       const AClaims: TClaims;
                       const AIsAuthenticated: Boolean); overload;
    constructor CreateAnonymous;
    destructor Destroy; override;

    /// True when the principal has `ARole` (case-insensitive).
    function HasRole(const ARole: string): Boolean;
    /// True when the principal has `AScope` (case-insensitive).
    function HasScope(const AScope: string): Boolean;
    /// Returns the claim value or AFallback when the key is missing.
    function ClaimOrDefault(const AKey, AFallback: string): string;

    property UserId: string read FUserId;
    property TenantId: string read FTenantId;
    property Roles: TArray<string> read FRoles;
    property Scopes: TArray<string> read FScopes;
    property Claims: TClaims read FClaims;
    property IsAuthenticated: Boolean read FIsAuthenticated;
  end;

  /// Raised when authentication is required but the principal is anonymous.
  /// Resolvers themselves do NOT raise -- they return False and the chain
  /// falls through to the next resolver. This exception is raised by
  /// THorseAuthorize.RequireAuthenticated.
  EHorseSessionUnauthorized = class(Exception);

  /// Raised when an authenticated principal lacks the required role/scope.
  /// Raised by THorseAuthorize.RequireRole / .RequireScope.
  EHorseSessionForbidden = class(Exception);

  /// Raised at configuration time when a resolver is given unusable
  /// settings (for example a signing key shorter than the HMAC floor).
  /// Never raised while a request is being resolved.
  EHorseSessionConfig = class(Exception);

/// Attaches APrincipal to the request. The request takes ownership: Horse
/// frees it at request end, and a principal already attached is freed and
/// replaced. Do not free APrincipal after this call.
procedure SetPrincipal(const AReq: THorseRequest; const APrincipal: TPrincipal);
/// The principal attached to the request, or nil when the horse-session
/// middleware has not run. The request owns it: never free the result.
function PrincipalOf(const AReq: THorseRequest): TPrincipal;
/// True when a principal is attached (authenticated or anonymous).
function TryGetPrincipal(const AReq: THorseRequest;
                         out APrincipal: TPrincipal): Boolean;

implementation

procedure SetPrincipal(const AReq: THorseRequest; const APrincipal: TPrincipal);
begin
  AReq.Sessions.SetSession(TPrincipal, APrincipal);
end;

function PrincipalOf(const AReq: THorseRequest): TPrincipal;
begin
  if AReq.Sessions.Contains(TPrincipal) then
    Result := TPrincipal(AReq.Sessions.Session[TPrincipal])
  else
    Result := nil;
end;

function TryGetPrincipal(const AReq: THorseRequest;
                         out APrincipal: TPrincipal): Boolean;
begin
  APrincipal := PrincipalOf(AReq);
  Result := APrincipal <> nil;
end;

{ TPrincipal }

constructor TPrincipal.Create(const AUserId, ATenantId: string;
                              const ARoles, AScopes: TArray<string>;
                              const AClaims: TClaims;
                              const AIsAuthenticated: Boolean);
begin
  inherited Create;
  FUserId := AUserId;
  FTenantId := ATenantId;
  FRoles := ARoles;
  FScopes := AScopes;
  if Assigned(AClaims) then
    FClaims := AClaims
  else
    FClaims := TClaims.Create;
  FIsAuthenticated := AIsAuthenticated;
end;

constructor TPrincipal.CreateAnonymous;
begin
  Create('', '', nil, nil, nil, False);
end;

destructor TPrincipal.Destroy;
begin
  FClaims.Free;
  inherited Destroy;
end;

function TPrincipal.HasRole(const ARole: string): Boolean;
var
  LItem: string;
begin
  Result := False;
  for LItem in FRoles do
    if SameText(LItem, ARole) then
      Exit(True);
end;

function TPrincipal.HasScope(const AScope: string): Boolean;
var
  LItem: string;
begin
  Result := False;
  for LItem in FScopes do
    if SameText(LItem, AScope) then
      Exit(True);
end;

function TPrincipal.ClaimOrDefault(const AKey, AFallback: string): string;
begin
  if not FClaims.TryGetValue(AKey, Result) then
    Result := AFallback;
end;

end.
