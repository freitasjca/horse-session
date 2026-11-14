unit Horse.Session.Jwt;

{$IF DEFINED(FPC)}{$MODE DELPHI}{$H+}{$ENDIF}

// =============================================================================
//  horse-session -- JWT HS256 resolver
//  -----------------------------------------------------------------------------
//  Reads Authorization: Bearer <token>, splits into header.payload.signature,
//  verifies the HMAC-SHA256 signature against a shared secret, enforces `exp`
//  and `nbf`, and maps standard claims into a TPrincipal:
//    sub         -> UserId (required)
//    tenant      -> TenantId (or 'tid' if 'tenant' absent)
//    roles       -> Roles (string-array claim, or a single string)
//    scope       -> Scopes (space-separated per RFC 8693)
//    *           -> Claims dictionary (strings as-is, other values as JSON)
//
//  v1 is HS256 only. Asymmetric algorithms (RS256, ES256) ship as a sibling
//  package horse-session-jwt-openssl, which pulls OpenSSL in dynamically.
//
//  Checks, in order (the first failure sets the reason code):
//    token-too-large            longer than JWT_MAX_TOKEN_CHARS
//    malformed-token            not three base64url segments / header not JSON
//    unsupported-alg            header alg is anything but exactly "HS256"
//                               (this is what rejects alg "none")
//    unsupported-crit           header carries a "crit" extension list
//    invalid-signature          HMAC mismatch (constant-time compare)
//    malformed-payload          payload is not a JSON object
//    missing-exp / invalid-exp / token-expired
//    invalid-nbf / token-not-yet-valid
//    issuer-mismatch / audience-mismatch   (only when configured)
//    missing-sub
//
//  The signature is verified before the payload is parsed, so no claim from
//  an unauthenticated token is ever interpreted.
//
//  The secret must be at least HORSE_SESSION_MIN_HMAC_KEY_BYTES (32) bytes,
//  as RFC 7518 section 3.2 requires; a shorter one raises
//  EHorseSessionConfig from the constructor.
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

const
  /// Tokens longer than this are refused before any decoding.
  JWT_MAX_TOKEN_CHARS = 8192;

type
  TJwtHS256Resolver = class(TInterfacedObject, IPrincipalResolver)
  strict private
    FSecret: TBytes;
    FExpectedIssuer: string;
    FExpectedAudience: string;
    FLeewaySeconds: Integer;
    FRequireExp: Boolean;
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
    /// Validates a bare token (no "Bearer " prefix). TryResolve calls this;
    /// it is public so a token can be checked without an HTTP request.
    function TryResolveToken(const AToken: string;
                             out APrincipal: TPrincipal;
                             out AReason: string): Boolean;
    function Name: string;
    class function New(const ASecret: string): IPrincipalResolver;
    /// When True (the default) a token without an `exp` claim is refused.
    property RequireExp: Boolean read FRequireExp write FRequireExp;
  end;

implementation

uses
{$IF DEFINED(FPC)}
  fpjson,
  jsonparser,
{$ELSE}
  System.JSON,
{$IFEND}
  Horse.Session.Crypto;

type
  TJwtObj = TJSONObject;
  TJwtArr = TJSONArray;
  TJwtAny = {$IF DEFINED(FPC)}TJSONData{$ELSE}TJSONValue{$IFEND};

{ --- JSON reading, compile-guarded across System.JSON and fpjson --------- }

function JwtParseObject(const AText: string): TJwtObj;
var
  LValue: TJwtAny;
begin
  // Delphi returns nil on invalid input, FPC raises. Normalise to nil.
  LValue := nil;
  try
{$IF DEFINED(FPC)}
    LValue := GetJSON(AText);
{$ELSE}
    LValue := TJSONObject.ParseJSONValue(AText);
{$IFEND}
  except
    Exit(nil);
  end;
  if (LValue = nil) or not (LValue is TJwtObj) then
  begin
    if LValue <> nil then
      LValue.Free;
    Exit(nil);
  end;
  Result := TJwtObj(LValue);
end;

function JwtFind(const AObj: TJwtObj; const AName: string): TJwtAny;
begin
{$IF DEFINED(FPC)}
  Result := AObj.Find(AName);
{$ELSE}
  Result := AObj.GetValue(AName);
{$IFEND}
end;

function JwtMemberCount(const AObj: TJwtObj): Integer;
begin
  Result := AObj.Count;
end;

function JwtMemberName(const AObj: TJwtObj; const AIndex: Integer): string;
begin
{$IF DEFINED(FPC)}
  Result := AObj.Names[AIndex];
{$ELSE}
  Result := AObj.Pairs[AIndex].JsonString.Value;
{$IFEND}
end;

function JwtMemberValue(const AObj: TJwtObj; const AIndex: Integer): TJwtAny;
begin
{$IF DEFINED(FPC)}
  Result := AObj.Items[AIndex];
{$ELSE}
  Result := AObj.Pairs[AIndex].JsonValue;
{$IFEND}
end;

function JwtIsNumber(const ANode: TJwtAny): Boolean;
begin
{$IF DEFINED(FPC)}
  Result := (ANode <> nil) and (ANode.JSONType = jtNumber);
{$ELSE}
  Result := (ANode <> nil) and (ANode is TJSONNumber);
{$IFEND}
end;

function JwtIsString(const ANode: TJwtAny): Boolean;
begin
{$IF DEFINED(FPC)}
  Result := (ANode <> nil) and (ANode.JSONType = jtString);
{$ELSE}
  // TJSONNumber descends from TJSONString on Delphi; exclude it.
  Result := (ANode <> nil) and (ANode is TJSONString) and
            not (ANode is TJSONNumber);
{$IFEND}
end;

function JwtIsArray(const ANode: TJwtAny): Boolean;
begin
  Result := (ANode <> nil) and (ANode is TJwtArr);
end;

/// String claims as their value, everything else as JSON text.
function JwtText(const ANode: TJwtAny): string;
begin
  if ANode = nil then
    Exit('');
{$IF DEFINED(FPC)}
  if ANode.JSONType = jtString then
    Result := ANode.AsString
  else
    Result := ANode.AsJSON;
{$ELSE}
  if ANode is TJSONString then
    Result := TJSONString(ANode).Value
  else
    Result := ANode.ToString;
{$IFEND}
end;

/// NumericDate (RFC 7519 section 2): a JSON number, fractions allowed.
function JwtNumericDate(const ANode: TJwtAny; out AValue: Int64): Boolean;
var
  LFloat: Double;
begin
  AValue := 0;
  Result := False;
  if not JwtIsNumber(ANode) then
    Exit;
  try
{$IF DEFINED(FPC)}
    LFloat := ANode.AsFloat;
{$ELSE}
    LFloat := TJSONNumber(ANode).AsDouble;
{$IFEND}
  except
    Exit;
  end;
  // 253402300799 = 9999-12-31T23:59:59Z; anything outside is not a date.
  if (LFloat < 0) or (LFloat > 253402300799.0) then
    Exit;
  AValue := Trunc(LFloat);
  Result := True;
end;

function JwtSplitSpaces(const AText: string): TArray<string>;
var
  LCount, LStart, I, LLen: Integer;
begin
  Result := nil;
  LLen := Length(AText);
  LCount := 0;
  SetLength(Result, LLen div 2 + 1);
  I := 1;
  while I <= LLen do
  begin
    while (I <= LLen) and (AText[I] = ' ') do
      Inc(I);
    LStart := I;
    while (I <= LLen) and (AText[I] <> ' ') do
      Inc(I);
    if I > LStart then
    begin
      Result[LCount] := Copy(AText, LStart, I - LStart);
      Inc(LCount);
    end;
  end;
  SetLength(Result, LCount);
end;

{ TJwtHS256Resolver }

constructor TJwtHS256Resolver.Create(const ASecret: string;
                                     const AExpectedIssuer: string;
                                     const AExpectedAudience: string;
                                     const ALeewaySeconds: Integer);
begin
  inherited Create;
  FSecret := Utf8BytesOf(ASecret);
  if Length(FSecret) < HORSE_SESSION_MIN_HMAC_KEY_BYTES then
    raise EHorseSessionConfig.CreateFmt(
      'JWT HS256 secret must be at least %d bytes (got %d)',
      [HORSE_SESSION_MIN_HMAC_KEY_BYTES, Length(FSecret)]);
  FExpectedIssuer := AExpectedIssuer;
  FExpectedAudience := AExpectedAudience;
  if ALeewaySeconds < 0 then
    FLeewaySeconds := 0
  else
    FLeewaySeconds := ALeewaySeconds;
  FRequireExp := True;
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
  Result := ConstantTimeBytesEqual(HmacSha256(FSecret, ASigningInput),
                                   ASignatureBytes);
end;

function TJwtHS256Resolver.BuildPrincipal(const APayloadJson: string;
                                          out APrincipal: TPrincipal;
                                          out AReason: string): Boolean;
var
  LObj: TJwtObj;
  LNode, LItem: TJwtAny;
  LArr: TJwtArr;
  LNow, LWhen: Int64;
  LUserId, LTenantId: string;
  LRoles, LScopes: TArray<string>;
  LClaims: TClaims;
  LAudienceOk: Boolean;
  I: Integer;
begin
  APrincipal := nil;
  AReason := '';
  Result := False;
  LRoles := nil;
  LScopes := nil;

  LObj := JwtParseObject(APayloadJson);
  if LObj = nil then
  begin
    AReason := 'malformed-payload';
    Exit;
  end;
  try
    LNow := UnixNowUtc;

    // exp: the token is valid strictly before exp (plus leeway).
    LNode := JwtFind(LObj, 'exp');
    if LNode = nil then
    begin
      if FRequireExp then
      begin
        AReason := 'missing-exp';
        Exit;
      end;
    end
    else
    begin
      if not JwtNumericDate(LNode, LWhen) then
      begin
        AReason := 'invalid-exp';
        Exit;
      end;
      if LNow >= LWhen + FLeewaySeconds then
      begin
        AReason := 'token-expired';
        Exit;
      end;
    end;

    // nbf: the token is not valid before nbf (minus leeway).
    LNode := JwtFind(LObj, 'nbf');
    if LNode <> nil then
    begin
      if not JwtNumericDate(LNode, LWhen) then
      begin
        AReason := 'invalid-nbf';
        Exit;
      end;
      if LNow + FLeewaySeconds < LWhen then
      begin
        AReason := 'token-not-yet-valid';
        Exit;
      end;
    end;

    if FExpectedIssuer <> '' then
    begin
      LNode := JwtFind(LObj, 'iss');
      if not (JwtIsString(LNode) and (JwtText(LNode) = FExpectedIssuer)) then
      begin
        AReason := 'issuer-mismatch';
        Exit;
      end;
    end;

    // aud is a single string or an array of strings (RFC 7519 section 4.1.3).
    if FExpectedAudience <> '' then
    begin
      LAudienceOk := False;
      LNode := JwtFind(LObj, 'aud');
      if JwtIsString(LNode) then
        LAudienceOk := JwtText(LNode) = FExpectedAudience
      else if JwtIsArray(LNode) then
      begin
        LArr := TJwtArr(LNode);
        for I := 0 to LArr.Count - 1 do
        begin
          LItem := LArr.Items[I];
          if JwtIsString(LItem) and (JwtText(LItem) = FExpectedAudience) then
            LAudienceOk := True;
        end;
      end;
      if not LAudienceOk then
      begin
        AReason := 'audience-mismatch';
        Exit;
      end;
    end;

    LNode := JwtFind(LObj, 'sub');
    if JwtIsString(LNode) then
      LUserId := JwtText(LNode)
    else
      LUserId := '';
    if LUserId = '' then
    begin
      AReason := 'missing-sub';
      Exit;
    end;

    LTenantId := '';
    LNode := JwtFind(LObj, 'tenant');
    if not JwtIsString(LNode) then
      LNode := JwtFind(LObj, 'tid');
    if JwtIsString(LNode) then
      LTenantId := JwtText(LNode);

    LNode := JwtFind(LObj, 'roles');
    if JwtIsArray(LNode) then
    begin
      LArr := TJwtArr(LNode);
      SetLength(LRoles, LArr.Count);
      for I := 0 to LArr.Count - 1 do
        LRoles[I] := JwtText(LArr.Items[I]);
    end
    else if JwtIsString(LNode) then
    begin
      SetLength(LRoles, 1);
      LRoles[0] := JwtText(LNode);
    end;

    LNode := JwtFind(LObj, 'scope');
    if JwtIsString(LNode) then
      LScopes := JwtSplitSpaces(JwtText(LNode));

    LClaims := TClaims.Create;
    try
      for I := 0 to JwtMemberCount(LObj) - 1 do
        LClaims.AddOrSetValue(JwtMemberName(LObj, I),
                              JwtText(JwtMemberValue(LObj, I)));
      APrincipal := TPrincipal.Create(LUserId, LTenantId, LRoles, LScopes,
                                      LClaims, True);
    except
      LClaims.Free;
      raise;
    end;
    Result := True;
  finally
    LObj.Free;
  end;
end;

function TJwtHS256Resolver.TryResolveToken(const AToken: string;
                                           out APrincipal: TPrincipal;
                                           out AReason: string): Boolean;
var
  LDot1, LDot2, LDots, I: Integer;
  LHeaderBytes, LPayloadBytes, LSignature: TBytes;
  LHeaderJson, LPayloadJson: string;
  LHeader: TJwtObj;
  LAlgOk, LHasCrit: Boolean;
begin
  APrincipal := nil;
  AReason := '';
  Result := False;

  if Length(AToken) > JWT_MAX_TOKEN_CHARS then
  begin
    AReason := 'token-too-large';
    Exit;
  end;

  // Exactly two dots, three segments, header and payload non-empty.
  LDot1 := 0;
  LDot2 := 0;
  LDots := 0;
  for I := 1 to Length(AToken) do
    if AToken[I] = '.' then
    begin
      Inc(LDots);
      if LDots = 1 then
        LDot1 := I
      else if LDots = 2 then
        LDot2 := I;
    end;
  AReason := 'malformed-token';
  if (LDots <> 2) or (LDot1 < 2) or (LDot2 = LDot1 + 1) then
    Exit;

  if not Base64UrlDecode(Copy(AToken, 1, LDot1 - 1), LHeaderBytes) then
    Exit;
  if not Base64UrlDecode(Copy(AToken, LDot1 + 1, LDot2 - LDot1 - 1), LPayloadBytes) then
    Exit;
  if not Base64UrlDecode(Copy(AToken, LDot2 + 1, MaxInt), LSignature) then
    Exit;
  if not Utf8StringOf(LHeaderBytes, LHeaderJson) then
    Exit;

  LHeader := JwtParseObject(LHeaderJson);
  if LHeader = nil then
    Exit;
  try
    LAlgOk := JwtIsString(JwtFind(LHeader, 'alg')) and
              (JwtText(JwtFind(LHeader, 'alg')) = 'HS256');
    LHasCrit := JwtFind(LHeader, 'crit') <> nil;
  finally
    LHeader.Free;
  end;
  if not LAlgOk then
  begin
    AReason := 'unsupported-alg';
    Exit;
  end;
  if LHasCrit then
  begin
    AReason := 'unsupported-crit';
    Exit;
  end;

  // Signing input is the first two segments exactly as received. Both are
  // base64url, so one byte per character is exact.
  if not VerifySignature(AsciiBytesOf(Copy(AToken, 1, LDot2 - 1)), LSignature) then
  begin
    AReason := 'invalid-signature';
    Exit;
  end;

  if not Utf8StringOf(LPayloadBytes, LPayloadJson) then
  begin
    AReason := 'malformed-payload';
    Exit;
  end;
  Result := BuildPrincipal(LPayloadJson, APrincipal, AReason);
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

  // Another scheme (Basic, Digest, ...) is not ours to judge: fall through.
  if not LAuth.StartsWith('Bearer ', True) then
    Exit;

  Result := TryResolveToken(Trim(Copy(LAuth, 8, MaxInt)), APrincipal, AReason);
end;

end.
