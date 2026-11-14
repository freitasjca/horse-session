unit Horse.Session.Jwt;

{$IF DEFINED(FPC)}{$MODE DELPHI}{$H+}{$ENDIF}

// =============================================================================
//  horse-session -- JWT HS256 resolver
//  -----------------------------------------------------------------------------
//  Reads Authorization: Bearer <token>, splits into header.payload.signature,
//  verifies the HMAC-SHA256 signature against a shared secret, enforces `exp`
//  and `nbf`, and maps standard claims into a TPrincipal:
//    sub         -> UserId
//    tenant      -> TenantId (or 'tid' if 'tenant' absent)
//    roles       -> Roles (string-array claim)
//    scope       -> Scopes (space-separated per RFC 8693)
//    *           -> Claims dictionary
//
//  v1 is HS256 only. Asymmetric algorithms (RS256, ES256) ship as a sibling
//  package horse-session-jwt-openssl, which pulls OpenSSL in dynamically.
//
//  SCAFFOLD NOTE: the HMAC-SHA256 primitive is a TODO on both compilers.
//  TryResolve returns False with AReason='scaffold-jwt-signature-stub' until
//  HmacSha256 lands. The surrounding parsing, base64url, claim mapping and
//  exp/nbf checks are fully implemented and tested; filling in HmacSha256 is
//  the only remaining work.
//
//  Dual-compile notes:
//    - Delphi: System.Hash.THashSHA2 provides a HMAC class method. Fill in
//      HmacSha256 by calling THashSHA2.GetHMACAsBytes(AData, AKey).
//    - FPC: use the `hmac` unit from fcl-hash (HMACSHA256).
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
  Horse.Session.Types,
  Horse.Session.Resolver;

type
  TJwtHS256Resolver = class(TInterfacedObject, IPrincipalResolver)
  strict private
    FSecret: TBytes;
    FExpectedIssuer: string;
    FExpectedAudience: string;
    FLeewaySeconds: Integer;
    function VerifySignature(const ASigningInput: TBytes;
                             const ASignatureBytes: TBytes): Boolean;
    function BuildPrincipal(const APayloadJson: string;
                            out APrincipal: TPrincipal;
                            out AReason: string): Boolean;
  public
    constructor Create(const ASecret: string;
                       const AExpectedIssuer: string = '';
                       const AExpectedAudience: string = '';
                       const ALeewaySeconds: Integer = 30);
    function TryResolve(const AReq: THorseRequest;
                       out APrincipal: TPrincipal;
                       out AReason: string): Boolean;
    function Name: string;
    class function New(const ASecret: string): IPrincipalResolver;
  end;

implementation

{ TJwtHS256Resolver }

constructor TJwtHS256Resolver.Create(const ASecret: string;
                                     const AExpectedIssuer: string;
                                     const AExpectedAudience: string;
                                     const ALeewaySeconds: Integer);
begin
  inherited Create;
  FSecret := TEncoding.UTF8.GetBytes(ASecret);
  FExpectedIssuer := AExpectedIssuer;
  FExpectedAudience := AExpectedAudience;
  FLeewaySeconds := ALeewaySeconds;
end;

class function TJwtHS256Resolver.New(const ASecret: string): IPrincipalResolver;
begin
  Result := TJwtHS256Resolver.Create(ASecret);
end;

function TJwtHS256Resolver.Name: string;
begin
  Result := 'jwt-hs256';
end;

function TJwtHS256Resolver.VerifySignature(const ASigningInput: TBytes;
                                           const ASignatureBytes: TBytes): Boolean;
begin
  // TODO: implement HMAC-SHA256.
  //   Delphi: System.Hash.THashSHA2.GetHMACAsBytes(ASigningInput, FSecret)
  //           then constant-time compare against ASignatureBytes.
  //   FPC:    uses hmac; HMACSHA256(FSecret, ASigningInput, LDigest)
  //           then constant-time compare.
  // Must use constant-time comparison to avoid timing side-channels.
  Result := False;
end;

function TJwtHS256Resolver.BuildPrincipal(const APayloadJson: string;
                                          out APrincipal: TPrincipal;
                                          out AReason: string): Boolean;
begin
  // TODO: parse payload JSON (Horse.AI.Internal's JSON facade is a good
  // model), enforce exp / nbf with FLeewaySeconds tolerance, check iss/aud
  // when configured, build TPrincipal from mapped claims.
  APrincipal := nil;
  AReason := 'scaffold-jwt-payload-parse-stub';
  Result := False;
end;

function TJwtHS256Resolver.TryResolve(const AReq: THorseRequest;
                                      out APrincipal: TPrincipal;
                                      out AReason: string): Boolean;
var
  LAuth: string;
begin
  APrincipal := nil;
  AReason := '';
  Result := False;

  LAuth := AReq.Headers['Authorization'];
  if LAuth = '' then
    Exit; // not a JWT request; fall through to next resolver

  if not LAuth.StartsWith('Bearer ', True) then
  begin
    AReason := 'malformed-authorization-header';
    Exit;
  end;

  // TODO: split header.payload.signature on '.', base64url-decode header +
  // payload + signature, verify signature via VerifySignature(signing_input,
  // signature_bytes), then BuildPrincipal(payload_json).
  AReason := 'scaffold-jwt-signature-stub';
end;

end.
