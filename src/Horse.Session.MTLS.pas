unit Horse.Session.MTLS;

{$IF DEFINED(FPC)}{$MODE DELPHI}{$H+}{$ENDIF}

// =============================================================================
//  horse-session -- mTLS peer-cert extension interface and resolver
//  -----------------------------------------------------------------------------
//  Horse core does not expose peer-certificate information uniformly across
//  providers; each provider that supports mTLS must publish IHorseTLSPeerCert
//  on the request. This unit defines the extension interface (provider-
//  agnostic) and the resolver that consumes it. The CrossSocket implementation
//  of the extension lives in Horse.Session.CrossSocket -- that unit is opt-in
//  (users add it to their uses clause to activate mTLS on CrossSocket).
//
//  Other providers (nghttp2, mORMot, ICS) implement IHorseTLSPeerCert in their
//  own repos in later releases; horse-session itself ships ONLY the contract
//  and the CrossSocket adapter.
//
//  SCAFFOLD NOTE: subject-DN -> UserId / TenantId mapping is a simple default
//  (CN -> UserId, O -> TenantId). Production deployments plug in their own
//  ICertSubjectMapper.
// =============================================================================

interface

uses
{$IF DEFINED(FPC)}
  SysUtils,
  Classes,
{$ELSE}
  System.SysUtils,
  System.Classes,
{$IFEND}
  Horse.Request,
  Horse.Session.Types,
  Horse.Session.Resolver;

type
  /// Peer-certificate accessor. Provider-specific units publish this on
  /// Req.Services so the mTLS resolver can read it provider-agnostically.
  ///
  /// IsVerified MUST reflect the TLS stack's own verification result --
  /// never return True for a cert that failed trust-chain validation.
  /// Certificate verification and trust-chain validation remain the
  /// responsibility of the TLS provider; this interface only surfaces the
  /// result.
  IHorseTLSPeerCert = interface
    ['{6D7E4B1A-8C50-4F93-A28F-1E5C7B9A4D62}']
    function IsVerified: Boolean;
    function SubjectCN: string;
    function SubjectO: string;
    function SubjectDN: string;        // full RFC 4514 DN string
    function SubjectAltNames: TArray<string>;   // DNS: / URI: / email: entries
    function SerialHex: string;
  end;

  /// Optional pluggable mapper from subject -> (UserId, TenantId, Roles).
  /// The default maps CN -> UserId, O -> TenantId, leaves Roles empty.
  ICertSubjectMapper = interface
    ['{7A8F5D2C-9E41-4B06-A5F3-4B6D1C8E7F94}']
    procedure Map(const APeer: IHorseTLSPeerCert;
                  out AUserId, ATenantId: string;
                  out ARoles, AScopes: TArray<string>);
  end;

  /// Default mapper: CN -> UserId, O -> TenantId, no roles / scopes.
  TDefaultCertSubjectMapper = class(TInterfacedObject, ICertSubjectMapper)
  public
    procedure Map(const APeer: IHorseTLSPeerCert;
                  out AUserId, ATenantId: string;
                  out ARoles, AScopes: TArray<string>);
  end;

  TMTLSResolver = class(TInterfacedObject, IPrincipalResolver)
  strict private
    FMapper: ICertSubjectMapper;
  public
    constructor Create(const AMapper: ICertSubjectMapper = nil);
    function TryResolve(const AReq: THorseRequest;
                       out APrincipal: TPrincipal;
                       out AReason: string): Boolean;
    function Name: string;
    class function New: IPrincipalResolver; overload;
    class function New(const AMapper: ICertSubjectMapper): IPrincipalResolver; overload;
  end;

implementation

{ TDefaultCertSubjectMapper }

procedure TDefaultCertSubjectMapper.Map(const APeer: IHorseTLSPeerCert;
                                        out AUserId, ATenantId: string;
                                        out ARoles, AScopes: TArray<string>);
begin
  AUserId := APeer.SubjectCN;
  ATenantId := APeer.SubjectO;
  SetLength(ARoles, 0);
  SetLength(AScopes, 0);
end;

{ TMTLSResolver }

constructor TMTLSResolver.Create(const AMapper: ICertSubjectMapper);
begin
  inherited Create;
  if AMapper <> nil then
    FMapper := AMapper
  else
    FMapper := TDefaultCertSubjectMapper.Create;
end;

class function TMTLSResolver.New: IPrincipalResolver;
begin
  Result := TMTLSResolver.Create(nil);
end;

class function TMTLSResolver.New(const AMapper: ICertSubjectMapper): IPrincipalResolver;
begin
  Result := TMTLSResolver.Create(AMapper);
end;

function TMTLSResolver.Name: string;
begin
  Result := 'mtls';
end;

function TMTLSResolver.TryResolve(const AReq: THorseRequest;
                                  out APrincipal: TPrincipal;
                                  out AReason: string): Boolean;
var
  LPeer: IHorseTLSPeerCert;
  LRaw: TObject;
  LUserId, LTenantId: string;
  LRoles, LScopes: TArray<string>;
begin
  APrincipal := nil;
  AReason := '';
  Result := False;

  // The extension is published on Req.Services by the provider adapter.
  // A provider that doesn't support mTLS doesn't publish it -> we fall
  // through silently (Reason='') to the next resolver.
  try
    LRaw := AReq.Services.Resolve(TObject);  // scaffold: provider adapter
                                             // will register under its own
                                             // TClass key
  except
    LRaw := nil;
  end;
  if (LRaw = nil) or not Supports(LRaw, IHorseTLSPeerCert, LPeer) then
    Exit;

  // The provider HAS surfaced a peer cert slot. From here, every failure
  // is explicit -- we must NEVER silently treat an absent/invalid cert as
  // an authenticated principal.
  if not LPeer.IsVerified then
  begin
    AReason := 'peer-cert-not-verified';
    Exit;
  end;

  FMapper.Map(LPeer, LUserId, LTenantId, LRoles, LScopes);
  if LUserId = '' then
  begin
    AReason := 'peer-cert-no-identity';
    Exit;
  end;

  APrincipal := TPrincipal.Create(LUserId, LTenantId, LRoles, LScopes,
                                  nil, True);
  Result := True;
end;

end.
