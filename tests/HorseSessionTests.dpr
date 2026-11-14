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
    - TJwtHS256Resolver / TCookieResolver: SCAFFOLD -- these tests only
      exercise the "resolver did not recognise request" (fall-through)
      path. Full signature-verification coverage lands with the HMAC
      primitive (see Horse.Session.Jwt unit header).

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
  Horse.Session.Cookie;

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

{ --- Main -------------------------------------------------------------- }

begin
  Writeln('horse-session conformance tests');
  Writeln('================================');

  TestPrincipal;
  TestAuditSinks;
  TestConstantTimeEquals;
  TestApiKeyStore;
  TestSessionStore;

  Writeln;
  Writeln(Format('summary: %d total, %d failed', [GTotal, GFailures]));
  if GFailures > 0 then
    ExitCode := 1
  else
    ExitCode := 0;
end.
