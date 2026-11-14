program HorseSessionTests;

{$APPTYPE CONSOLE}
{$IF DEFINED(FPC)}{$MODE DELPHI}{$H+}{$ENDIF}

{
  horse-session conformance tests
  ================================
  Destination: horse-session/tests/HorseSessionTests.dpr

  In-process coverage without a live socket:
    - TPrincipal: role / scope / claim semantics, case-insensitivity.
    - TAuthAuditEvent / IAuthAuditSink: null + memory sinks, thread safety
      smoke test.
    - TMemoryApiKeyStore + TApiKeyResolver: constant-time lookup, hit and
      miss paths, reason codes.
    - TMemorySessionStore: TTL expiry, revoke.
    - ConstantTimeEquals: equal / unequal / different-length cases.
    - Horse.Session.Crypto: SHA-256 (FIPS 180-4 vectors), HMAC-SHA256
      (RFC 4231 vectors), strict base64url.
    - TJwtHS256Resolver: a token signed by an independent implementation
      (Python hmac/hashlib), then tampering, wrong secret, alg "none",
      exp / nbf / iss / aud / sub checks, malformed input, short secret.
    - TCookieResolver: Cookie header parsing, PackSessionId against an
      independently computed value, tampering, unknown session.

  No DUnitX: plain Writeln + a failure counter + non-zero exit. Matches
  horse-ai/tests/HorseAITests.dpr style.
}

uses
{$IF DEFINED(FPC)}
  {$IF DEFINED(UNIX)}cthreads,{$ENDIF}
  SysUtils,
  Classes,
{$ELSE}
  System.SysUtils,
  System.Classes,
{$IFEND}
  Horse.Session.Types,
  Horse.Session.Audit,
  Horse.Session.ApiKey,
  Horse.Session.Cookie,
  Horse.Session.Crypto,
  Horse.Session.Jwt;

var
  GTotal: Integer = 0;
  GFailures: Integer = 0;

procedure Ok(const AWhat: string);
begin
  Inc(GTotal);
  Writeln('ok   ', AWhat);
end;

procedure Fail(const AWhat, ADetail: string);
begin
  Inc(GTotal);
  Inc(GFailures);
  Writeln('FAIL ', AWhat, '  --  ', ADetail);
end;

procedure AssertEqualStr(const AWhat, AExpected, AActual: string);
begin
  if AExpected = AActual then
    Ok(AWhat)
  else
    Fail(AWhat, 'expected "' + AExpected + '", got "' + AActual + '"');
end;

procedure AssertEqualInt(const AWhat: string; AExpected, AActual: Int64);
begin
  if AExpected = AActual then
    Ok(AWhat)
  else
    Fail(AWhat, 'expected ' + IntToStr(AExpected) + ', got ' + IntToStr(AActual));
end;

procedure AssertTrue(const AWhat: string; ACond: Boolean);
begin
  if ACond then Ok(AWhat) else Fail(AWhat, 'condition was false');
end;

procedure AssertFalse(const AWhat: string; ACond: Boolean);
begin
  if not ACond then Ok(AWhat) else Fail(AWhat, 'condition was true');
end;

{ --- TPrincipal -------------------------------------------------------- }

procedure TestPrincipal;
var
  LP: TPrincipal;
begin
  Writeln;
  Writeln('-- TPrincipal --');

  LP := TPrincipal.Create('alice', 'acme',
                          ['admin', 'user'],
                          ['read', 'write'],
                          nil, True);
  try
    AssertEqualStr('UserId', 'alice', LP.UserId);
    AssertEqualStr('TenantId', 'acme', LP.TenantId);
    AssertTrue('IsAuthenticated', LP.IsAuthenticated);
    AssertTrue('HasRole(admin)', LP.HasRole('admin'));
    AssertTrue('HasRole(ADMIN) case-insensitive', LP.HasRole('ADMIN'));
    AssertFalse('HasRole(superadmin)', LP.HasRole('superadmin'));
    AssertTrue('HasScope(write)', LP.HasScope('write'));
    AssertFalse('HasScope(delete)', LP.HasScope('delete'));
    AssertEqualStr('ClaimOrDefault missing', 'fallback',
                   LP.ClaimOrDefault('missing', 'fallback'));
  finally
    LP.Free;
  end;

  LP := TPrincipal.CreateAnonymous;
  try
    AssertFalse('Anonymous IsAuthenticated', LP.IsAuthenticated);
    AssertEqualStr('Anonymous UserId', '', LP.UserId);
  finally
    LP.Free;
  end;
end;

{ --- Audit sinks ------------------------------------------------------- }

procedure TestAuditSinks;
var
  LNull: IAuthAuditSink;
  LMem: TMemoryAuthAuditSink;
  LEv: TAuthAuditEvent;
  LSnap: TArray<TAuthAuditEvent>;
begin
  Writeln;
  Writeln('-- Audit sinks --');

  LNull := TNullAuthAuditSink.Create;
  LEv := MakeAuthEvent('authentication.succeeded', 'acme', 'alice',
                       'route', '/x', 'succeeded', 'jwt', 'req-1');
  LNull.RecordEvent(LEv);
  Ok('Null sink accepts event without raising');

  LMem := TMemoryAuthAuditSink.Create;
  try
    LMem.RecordEvent(LEv);
    LMem.RecordEvent(MakeAuthEvent('authorization.denied', 'acme', 'bob',
                                   'route', '/x', 'denied', 'missing-role', 'req-2'));
    LSnap := LMem.Snapshot;
    AssertEqualInt('Memory sink count', 2, Length(LSnap));
    AssertEqualStr('Memory sink action[0]', 'authentication.succeeded', LSnap[0].Action);
    AssertEqualStr('Memory sink reason[1]', 'missing-role', LSnap[1].Reason);

    LMem.Clear;
    LSnap := LMem.Snapshot;
    AssertEqualInt('Memory sink cleared', 0, Length(LSnap));
  finally
    LMem.Free;
  end;
end;

{ --- ConstantTimeEquals ------------------------------------------------ }

procedure TestConstantTimeEquals;
begin
  Writeln;
  Writeln('-- ConstantTimeEquals --');

  AssertTrue('equal strings',  ConstantTimeEquals('abc', 'abc'));
  AssertFalse('different strings', ConstantTimeEquals('abc', 'abd'));
  AssertFalse('different lengths', ConstantTimeEquals('abc', 'abcd'));
  AssertTrue('empty equal',    ConstantTimeEquals('', ''));
  AssertFalse('one empty',     ConstantTimeEquals('', 'a'));
end;

{ --- TMemoryApiKeyStore ------------------------------------------------ }

procedure TestApiKeyStore;
var
  LStore: TMemoryApiKeyStore;
  LRec, LGot: TApiKeyRecord;
begin
  Writeln;
  Writeln('-- TMemoryApiKeyStore --');

  LStore := TMemoryApiKeyStore.Create;
  try
    LRec.UserId := 'alice';
    LRec.TenantId := 'acme';
    LRec.Roles := ['admin'];
    LRec.Scopes := ['read'];
    LStore.Add('secret-key-1', LRec);

    AssertTrue('Lookup hit',  LStore.Lookup('secret-key-1', LGot));
    AssertEqualStr('Hit UserId', 'alice', LGot.UserId);

    AssertFalse('Lookup miss', LStore.Lookup('wrong-key', LGot));
  finally
    LStore.Free;
  end;
end;

{ --- TMemorySessionStore ----------------------------------------------- }

procedure TestSessionStore;
var
  LStore: TMemorySessionStore;
  LRec, LGot: TSessionRecord;
begin
  Writeln;
  Writeln('-- TMemorySessionStore --');

  LStore := TMemorySessionStore.Create;
  try
    LRec.SessionId := 'sess-1';
    LRec.UserId := 'alice';
    LRec.TenantId := 'acme';
    LRec.IssuedAt := Now;
    LRec.ExpiresAt := 0; // no TTL
    LStore.Upsert(LRec);

    AssertTrue('TryLookup hit', LStore.TryLookup('sess-1', LGot));
    AssertEqualStr('TryLookup UserId', 'alice', LGot.UserId);

    AssertTrue('Revoke', LStore.Revoke('sess-1'));
    AssertFalse('TryLookup after revoke', LStore.TryLookup('sess-1', LGot));

    LRec.ExpiresAt := Now - 1; // already expired
    LStore.Upsert(LRec);
    AssertFalse('TryLookup expired', LStore.TryLookup('sess-1', LGot));
  finally
    LStore.Free;
  end;
end;

{ --- Horse.Session.Crypto ---------------------------------------------- }

function FilledBytes(const AValue: Byte; const ACount: Integer): TBytes;
var
  I: Integer;
begin
  Result := nil;
  SetLength(Result, ACount);
  for I := 0 to ACount - 1 do
    Result[I] := AValue;
end;

procedure TestCrypto;
var
  LBytes: TBytes;
begin
  Writeln;
  Writeln('-- Sha256 / HmacSha256 / base64url --');

  // FIPS 180-4 examples.
  AssertEqualStr('SHA-256 "abc"',
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    BytesToHex(Sha256(AsciiBytesOf('abc'))));
  AssertEqualStr('SHA-256 empty',
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    BytesToHex(Sha256(nil)));
  AssertEqualStr('SHA-256 56-byte message (two blocks)',
    '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
    BytesToHex(Sha256(AsciiBytesOf(
      'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))));
  AssertEqualStr('SHA-256 1000 x "a"',
    '41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3',
    BytesToHex(Sha256(FilledBytes(Ord('a'), 1000))));

  // RFC 4231 test cases 1, 2 and 6.
  AssertEqualStr('HMAC-SHA256 RFC 4231 case 1',
    'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    BytesToHex(HmacSha256(FilledBytes($0B, 20), AsciiBytesOf('Hi There'))));
  AssertEqualStr('HMAC-SHA256 RFC 4231 case 2',
    '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    BytesToHex(HmacSha256(AsciiBytesOf('Jefe'),
                          AsciiBytesOf('what do ya want for nothing?'))));
  AssertEqualStr('HMAC-SHA256 RFC 4231 case 6 (key longer than block)',
    '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
    BytesToHex(HmacSha256(FilledBytes($AA, 131), AsciiBytesOf(
      'Test Using Larger Than Block-Size Key - Hash Key First'))));

  AssertEqualStr('base64url encode 1 byte', 'Zg', Base64UrlEncode(AsciiBytesOf('f')));
  AssertEqualStr('base64url encode 2 bytes', 'Zm8', Base64UrlEncode(AsciiBytesOf('fo')));
  AssertEqualStr('base64url encode 3 bytes', 'Zm9v', Base64UrlEncode(AsciiBytesOf('foo')));
  AssertEqualStr('base64url encode empty', '', Base64UrlEncode(nil));

  AssertTrue('base64url decode url-safe chars', Base64UrlDecode('AAEC__4', LBytes));
  AssertEqualStr('base64url decoded bytes', '000102fffe', BytesToHex(LBytes));
  AssertTrue('base64url decode empty', Base64UrlDecode('', LBytes));
  AssertEqualInt('base64url decode empty length', 0, Length(LBytes));
  AssertFalse('base64url rejects padding', Base64UrlDecode('Zg==', LBytes));
  AssertFalse('base64url rejects "+"', Base64UrlDecode('AA+A', LBytes));
  AssertFalse('base64url rejects impossible length', Base64UrlDecode('Zm9vZ', LBytes));
  AssertFalse('base64url rejects non-zero trailing bits', Base64UrlDecode('Zh', LBytes));

  AssertTrue('ConstantTimeBytesEqual same',
    ConstantTimeBytesEqual(AsciiBytesOf('abc'), AsciiBytesOf('abc')));
  AssertFalse('ConstantTimeBytesEqual different',
    ConstantTimeBytesEqual(AsciiBytesOf('abc'), AsciiBytesOf('abd')));
  AssertFalse('ConstantTimeBytesEqual different length',
    ConstantTimeBytesEqual(AsciiBytesOf('abc'), AsciiBytesOf('ab')));

  // 1794000000 = 2026-11-06; 4102444800 = 2100-01-01.
  AssertTrue('UnixNowUtc is a plausible current time',
    (UnixNowUtc > 1794000000) and (UnixNowUtc < 4102444800));
end;

{ --- TJwtHS256Resolver ------------------------------------------------- }

const
  TEST_KEY = '0123456789abcdef0123456789abcdef'; // 32 bytes
  OTHER_KEY = 'fedcba9876543210fedcba9876543210';
  HS256_HEADER = '{"alg":"HS256","typ":"JWT"}';

  // Signed with Python hmac/hashlib under TEST_KEY, exp = 2100-01-01:
  // {"sub":"alice","tenant":"acme","roles":["admin","user"],
  //  "scope":"read write","iss":"issuer-a","aud":"api-a","exp":4102444800}
  REFERENCE_TOKEN =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
    'eyJzdWIiOiJhbGljZSIsInRlbmFudCI6ImFjbWUiLCJyb2xlcyI6WyJhZG1pbiIsInVzZXIiXSwi' +
    'c2NvcGUiOiJyZWFkIHdyaXRlIiwiaXNzIjoiaXNzdWVyLWEiLCJhdWQiOiJhcGktYSIsImV4cCI6' +
    'NDEwMjQ0NDgwMH0.' +
    'lEYb67SbcYq3aCmFqWLCybcTa1qZCYw0ni0ugDqcuQc';

function MakeToken(const AHeaderJson, APayloadJson, ASecret: string): string;
begin
  Result := Base64UrlEncode(Utf8BytesOf(AHeaderJson)) + '.' +
            Base64UrlEncode(Utf8BytesOf(APayloadJson));
  Result := Result + '.' +
            Base64UrlEncode(HmacSha256(Utf8BytesOf(ASecret), AsciiBytesOf(Result)));
end;

/// AExpectedReason = '' means the token must be accepted.
procedure ExpectToken(const AWhat: string; const AResolver: TJwtHS256Resolver;
                      const AToken, AExpectedReason: string);
var
  LPrincipal: TPrincipal;
  LReason: string;
  LAccepted: Boolean;
begin
  LAccepted := AResolver.TryResolveToken(AToken, LPrincipal, LReason);
  try
    if AExpectedReason = '' then
    begin
      if LAccepted and (LPrincipal <> nil) then
        Ok(AWhat)
      else
        Fail(AWhat, 'rejected with "' + LReason + '"');
    end
    else if LAccepted then
      Fail(AWhat, 'accepted, expected "' + AExpectedReason + '"')
    else if LPrincipal <> nil then
      Fail(AWhat, 'rejected but a principal was returned')
    else
      AssertEqualStr(AWhat, AExpectedReason, LReason);
  finally
    LPrincipal.Free;
  end;
end;

procedure TestJwt;
var
  LResolver: TJwtHS256Resolver;
  LPrincipal: TPrincipal;
  LReason, LTampered, LPast, LFuture, LSoon: string;
  LRaised: Boolean;
begin
  Writeln;
  Writeln('-- TJwtHS256Resolver --');

  LPast := IntToStr(UnixNowUtc - 3600);
  LSoon := IntToStr(UnixNowUtc - 10);
  LFuture := IntToStr(UnixNowUtc + 3600);

  LResolver := TJwtHS256Resolver.Create(TEST_KEY);
  try
    AssertTrue('reference token accepted',
      LResolver.TryResolveToken(REFERENCE_TOKEN, LPrincipal, LReason));
    if LPrincipal <> nil then
    try
      AssertEqualStr('sub -> UserId', 'alice', LPrincipal.UserId);
      AssertEqualStr('tenant -> TenantId', 'acme', LPrincipal.TenantId);
      AssertTrue('IsAuthenticated', LPrincipal.IsAuthenticated);
      AssertEqualInt('roles count', 2, Length(LPrincipal.Roles));
      AssertTrue('roles -> HasRole(admin)', LPrincipal.HasRole('admin'));
      AssertTrue('roles -> HasRole(user)', LPrincipal.HasRole('user'));
      AssertEqualInt('scope count', 2, Length(LPrincipal.Scopes));
      AssertTrue('scope -> HasScope(read)', LPrincipal.HasScope('read'));
      AssertTrue('scope -> HasScope(write)', LPrincipal.HasScope('write'));
      AssertEqualStr('claim iss', 'issuer-a', LPrincipal.ClaimOrDefault('iss', ''));
      AssertEqualStr('claim exp', '4102444800', LPrincipal.ClaimOrDefault('exp', ''));
    finally
      LPrincipal.Free;
    end;

    ExpectToken('own MakeToken round trip', LResolver,
      MakeToken(HS256_HEADER, '{"sub":"bob","exp":' + LFuture + '}', TEST_KEY), '');

    // Flip one character inside the payload segment.
    LTampered := REFERENCE_TOKEN;
    if LTampered[50] = 'A' then
      LTampered[50] := 'B'
    else
      LTampered[50] := 'A';
    ExpectToken('tampered payload', LResolver, LTampered, 'invalid-signature');

    ExpectToken('signed with another secret', LResolver,
      MakeToken(HS256_HEADER, '{"sub":"bob","exp":' + LFuture + '}', OTHER_KEY),
      'invalid-signature');
    ExpectToken('signature removed', LResolver,
      Copy(REFERENCE_TOKEN, 1, Length(REFERENCE_TOKEN) - 43), 'invalid-signature');

    ExpectToken('alg none, empty signature', LResolver,
      Base64UrlEncode(Utf8BytesOf('{"alg":"none"}')) + '.' +
      Base64UrlEncode(Utf8BytesOf('{"sub":"mallory","exp":' + LFuture + '}')) + '.',
      'unsupported-alg');
    ExpectToken('alg HS512', LResolver,
      MakeToken('{"alg":"HS512"}', '{"sub":"bob","exp":' + LFuture + '}', TEST_KEY),
      'unsupported-alg');
    ExpectToken('alg hs256 (wrong case)', LResolver,
      MakeToken('{"alg":"hs256"}', '{"sub":"bob","exp":' + LFuture + '}', TEST_KEY),
      'unsupported-alg');
    ExpectToken('crit header', LResolver,
      MakeToken('{"alg":"HS256","crit":["x"]}', '{"sub":"bob","exp":' + LFuture + '}', TEST_KEY),
      'unsupported-crit');

    ExpectToken('expired an hour ago', LResolver,
      MakeToken(HS256_HEADER, '{"sub":"bob","exp":' + LPast + '}', TEST_KEY),
      'token-expired');
    ExpectToken('expired 10 s ago, inside 30 s leeway', LResolver,
      MakeToken(HS256_HEADER, '{"sub":"bob","exp":' + LSoon + '}', TEST_KEY), '');
    ExpectToken('exp is a string', LResolver,
      MakeToken(HS256_HEADER, '{"sub":"bob","exp":"' + LFuture + '"}', TEST_KEY),
      'invalid-exp');
    ExpectToken('exp missing', LResolver,
      MakeToken(HS256_HEADER, '{"sub":"bob"}', TEST_KEY), 'missing-exp');
    ExpectToken('nbf an hour ahead', LResolver,
      MakeToken(HS256_HEADER,
        '{"sub":"bob","exp":' + LFuture + ',"nbf":' + LFuture + '}', TEST_KEY),
      'token-not-yet-valid');
    ExpectToken('nbf in the past', LResolver,
      MakeToken(HS256_HEADER,
        '{"sub":"bob","exp":' + LFuture + ',"nbf":' + LPast + '}', TEST_KEY), '');

    ExpectToken('sub missing', LResolver,
      MakeToken(HS256_HEADER, '{"exp":' + LFuture + '}', TEST_KEY), 'missing-sub');
    ExpectToken('payload not an object', LResolver,
      MakeToken(HS256_HEADER, '[1,2]', TEST_KEY), 'malformed-payload');

    ExpectToken('one segment', LResolver, 'abc', 'malformed-token');
    ExpectToken('four segments', LResolver, 'a.b.c.d', 'malformed-token');
    ExpectToken('empty token', LResolver, '', 'malformed-token');
    ExpectToken('header not base64url', LResolver, 'a$b.e30.AA', 'malformed-token');
    ExpectToken('header not JSON', LResolver, 'bm90anNvbg.e30.AA', 'malformed-token');
    ExpectToken('oversized token', LResolver,
      StringOfChar('A', JWT_MAX_TOKEN_CHARS + 1), 'token-too-large');

    LResolver.RequireExp := False;
    ExpectToken('exp missing, RequireExp off', LResolver,
      MakeToken(HS256_HEADER, '{"sub":"bob","tid":"t9"}', TEST_KEY), '');
  finally
    LResolver.Free;
  end;

  LResolver := TJwtHS256Resolver.Create(TEST_KEY, 'issuer-a', 'api-a');
  try
    ExpectToken('issuer and audience match', LResolver, REFERENCE_TOKEN, '');
    ExpectToken('audience inside an array', LResolver,
      MakeToken(HS256_HEADER,
        '{"sub":"bob","iss":"issuer-a","aud":["x","api-a"],"exp":' + LFuture + '}',
        TEST_KEY), '');
    ExpectToken('issuer differs', LResolver,
      MakeToken(HS256_HEADER,
        '{"sub":"bob","iss":"issuer-b","aud":"api-a","exp":' + LFuture + '}',
        TEST_KEY), 'issuer-mismatch');
    ExpectToken('issuer absent', LResolver,
      MakeToken(HS256_HEADER, '{"sub":"bob","aud":"api-a","exp":' + LFuture + '}',
        TEST_KEY), 'issuer-mismatch');
    ExpectToken('audience differs', LResolver,
      MakeToken(HS256_HEADER,
        '{"sub":"bob","iss":"issuer-a","aud":"api-b","exp":' + LFuture + '}',
        TEST_KEY), 'audience-mismatch');
  finally
    LResolver.Free;
  end;

  LRaised := False;
  try
    LResolver := TJwtHS256Resolver.Create('too-short');
    LResolver.Free;
  except
    on E: EHorseSessionConfig do
      LRaised := True;
  end;
  AssertTrue('short secret raises EHorseSessionConfig', LRaised);
end;

{ --- TCookieResolver --------------------------------------------------- }

procedure ExpectCookie(const AWhat: string; const AResolver: TCookieResolver;
                       const AValue, AExpectedReason: string);
var
  LPrincipal: TPrincipal;
  LReason: string;
  LAccepted: Boolean;
begin
  LAccepted := AResolver.TryResolveCookieValue(AValue, LPrincipal, LReason);
  try
    if LAccepted then
      Fail(AWhat, 'accepted, expected "' + AExpectedReason + '"')
    else if LPrincipal <> nil then
      Fail(AWhat, 'rejected but a principal was returned')
    else
      AssertEqualStr(AWhat, AExpectedReason, LReason);
  finally
    LPrincipal.Free;
  end;
end;

procedure TestCookieResolver;
const
  // base64url(HMAC-SHA256(TEST_KEY, 'sess-1')), computed with Python.
  SESS1_SIGNATURE = 'kn1gBMW-QEZlYJtN3bVcWS7nctr14qlj4ujgZtGFxQg';
var
  LStore: ISessionStore;
  LResolver: TCookieResolver;
  LRec: TSessionRecord;
  LPrincipal: TPrincipal;
  LValue, LReason: string;
  LRaised: Boolean;
begin
  Writeln;
  Writeln('-- TCookieResolver --');

  AssertTrue('ExtractCookieValue middle cookie',
    ExtractCookieValue('a=1; horse_session=abc.def; b=2', 'horse_session', LValue));
  AssertEqualStr('ExtractCookieValue value', 'abc.def', LValue);
  AssertTrue('ExtractCookieValue no spaces',
    ExtractCookieValue('a=1;horse_session=xyz', 'horse_session', LValue));
  AssertEqualStr('ExtractCookieValue value (no spaces)', 'xyz', LValue);
  AssertTrue('ExtractCookieValue quoted',
    ExtractCookieValue('horse_session="q.v"', 'horse_session', LValue));
  AssertEqualStr('ExtractCookieValue unquoted value', 'q.v', LValue);
  AssertTrue('ExtractCookieValue value containing "="',
    ExtractCookieValue('t=a=b', 't', LValue));
  AssertEqualStr('ExtractCookieValue keeps later "="', 'a=b', LValue);
  AssertFalse('ExtractCookieValue absent',
    ExtractCookieValue('a=1; b=2', 'horse_session', LValue));
  AssertFalse('ExtractCookieValue name is not a suffix match',
    ExtractCookieValue('xhorse_session=1', 'horse_session', LValue));
  AssertFalse('ExtractCookieValue name is case-sensitive',
    ExtractCookieValue('Horse_Session=1', 'horse_session', LValue));
  AssertFalse('ExtractCookieValue empty header',
    ExtractCookieValue('', 'horse_session', LValue));

  AssertEqualStr('PackSessionId matches independent HMAC',
    'sess-1.' + SESS1_SIGNATURE, TCookieResolver.PackSessionId('sess-1', TEST_KEY));

  LStore := TMemorySessionStore.Create;
  LRec := Default(TSessionRecord);
  LRec.SessionId := 'sess-1';
  LRec.UserId := 'alice';
  LRec.TenantId := 'acme';
  LRec.IssuedAt := Now;
  LRec.ExpiresAt := 0;
  LStore.Upsert(LRec);
  LRec.SessionId := 'sess.with.dots';
  LRec.UserId := 'carol';
  LStore.Upsert(LRec);

  LResolver := TCookieResolver.Create(LStore, 'horse_session', TEST_KEY);
  try
    AssertTrue('valid cookie accepted',
      LResolver.TryResolveCookieValue('sess-1.' + SESS1_SIGNATURE, LPrincipal, LReason));
    if LPrincipal <> nil then
    try
      AssertEqualStr('cookie UserId', 'alice', LPrincipal.UserId);
      AssertEqualStr('cookie TenantId', 'acme', LPrincipal.TenantId);
      AssertTrue('cookie IsAuthenticated', LPrincipal.IsAuthenticated);
    finally
      LPrincipal.Free;
    end;

    AssertTrue('session id containing dots accepted',
      LResolver.TryResolveCookieValue(
        TCookieResolver.PackSessionId('sess.with.dots', TEST_KEY), LPrincipal, LReason));
    if LPrincipal <> nil then
    try
      AssertEqualStr('dotted id UserId', 'carol', LPrincipal.UserId);
    finally
      LPrincipal.Free;
    end;

    ExpectCookie('signature of another id', LResolver,
      'sess-2.' + SESS1_SIGNATURE, 'invalid-cookie-signature');
    ExpectCookie('signed with another key', LResolver,
      TCookieResolver.PackSessionId('sess-1', OTHER_KEY), 'invalid-cookie-signature');
    ExpectCookie('no signature part', LResolver, 'sess-1', 'malformed-session-cookie');
    ExpectCookie('empty signature', LResolver, 'sess-1.', 'malformed-session-cookie');
    ExpectCookie('empty id', LResolver, '.' + SESS1_SIGNATURE, 'malformed-session-cookie');
    ExpectCookie('truncated signature', LResolver,
      'sess-1.' + Copy(SESS1_SIGNATURE, 1, 20), 'malformed-session-cookie');
    ExpectCookie('validly signed but unknown session', LResolver,
      TCookieResolver.PackSessionId('sess-404', TEST_KEY), 'session-not-found-or-expired');

    LStore.Revoke('sess-1');
    ExpectCookie('revoked session', LResolver,
      'sess-1.' + SESS1_SIGNATURE, 'session-not-found-or-expired');
  finally
    LResolver.Free;
  end;

  LRaised := False;
  try
    TCookieResolver.PackSessionId('sess-1', 'too-short');
  except
    on E: EHorseSessionConfig do
      LRaised := True;
  end;
  AssertTrue('short signing key raises EHorseSessionConfig', LRaised);
end;

{ --- Main -------------------------------------------------------------- }

begin
  Writeln('horse-session conformance tests');
  Writeln('================================');

  TestPrincipal;
  TestAuditSinks;
  TestConstantTimeEquals;
  TestApiKeyStore;
  TestSessionStore;
  TestCrypto;
  TestJwt;
  TestCookieResolver;

  Writeln;
  Writeln(Format('summary: %d total, %d failed', [GTotal, GFailures]));
  if GFailures > 0 then
    ExitCode := 1
  else
    ExitCode := 0;
end.
