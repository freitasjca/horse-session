unit Horse.Session.Types;

{$IF DEFINED(FPC)}{$MODE DELPHI}{$H+}{$ENDIF}

// =============================================================================
//  horse-session -- shared data types and ecosystem constants
//  -----------------------------------------------------------------------------
//  TPrincipal is the identity contract every resolver populates and every
//  downstream consumer reads. The HORSE_SESSION_PRINCIPAL_KEY constant is the
//  well-known Req.Session key under which the principal is attached -- sibling
//  packages (horse-ai-conversations in v1, future consumers) import this
//  constant rather than redeclaring the string literal.
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
  Generics.Collections;
{$ELSE}
  System.SysUtils,
  System.Generics.Collections;
{$IFEND}

const
  /// Well-known Req.Session key under which horse-session writes the
  /// authenticated principal. Sibling packages (horse-ai-conversations,
  /// future audit consumers) import this constant, not a local literal.
  HORSE_SESSION_PRINCIPAL_KEY = 'horse-session.principal';

type
  /// Claims bag -- opaque, string-to-string, extension point for anything
  /// the native TPrincipal fields don't cover.
  TClaims = TDictionary<string, string>;

  /// Authenticated principal. Immutable after the resolver chain completes:
  /// downstream middleware reads but never mutates it.
  TPrincipal = class
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

implementation

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
