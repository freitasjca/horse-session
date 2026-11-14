unit Horse.Session.Authorize;

{$IF DEFINED(FPC)}{$MODE DELPHI}{$H+}{$ENDIF}

// =============================================================================
//  horse-session -- role/scope authorization helpers
//  -----------------------------------------------------------------------------
//  Short-circuit middleware that reads the authenticated principal from
//  Req.Session[HORSE_SESSION_PRINCIPAL_KEY] and checks a required role or
//  scope. Fails fast:
//    - no principal, or IsAuthenticated=False -> 401
//    - authenticated but lacking role/scope   -> 403
//
//  Uses THorseSessionGuardConfig globals set by horse-session so that
//  authorization decisions emit audit events through the shared sink.
//
//  Shape-of-things-to-come: v2 adds Require(expression) with an AND/OR
//  parser. v1 only has the three single-predicate builders.
//
//  FPC NOTE: THorseCallback on FPC without FUNCTIONREFERENCES is a plain
//  procedure pointer. The Require* functions return unit-scope procedures
//  installed via globals, matching the Horse.CORS / horse-request-guard
//  pattern. Trade-off: role/scope state is process-wide. For scaffold
//  purposes this is sufficient; v2 lifts the limitation if needed.
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
  Horse.Response,
  Horse.Callback,
  Horse.Proc,
  Horse.Session.Types;

type
  THorseAuthorize = class
  public
    class function RequireAuthenticated: THorseCallback;
    class function RequireRole(const ARole: string): THorseCallback;
    class function RequireScope(const AScope: string): THorseCallback;
  end;

implementation

uses
  Horse.Exception.Interrupted;

var
  GRequiredRole: string;
  GRequiredScope: string;
  GRequireKind: Integer; // 0=none, 1=authenticated, 2=role, 3=scope

function ReadPrincipal(AReq: THorseRequest): TPrincipal;
var
  LObj: TObject;
begin
  Result := nil;
  if AReq.Session.ContainsKey(HORSE_SESSION_PRINCIPAL_KEY) then
  begin
    LObj := TObject(AReq.Session[HORSE_SESSION_PRINCIPAL_KEY]);
    if LObj is TPrincipal then
      Result := TPrincipal(LObj);
  end;
end;

procedure AuthorizeProc(AReq: THorseRequest; ARes: THorseResponse; ANext: TNextProc);
var
  LPrincipal: TPrincipal;
begin
  LPrincipal := ReadPrincipal(AReq);

  if (LPrincipal = nil) or not LPrincipal.IsAuthenticated then
  begin
    ARes.Status(401).Send('Unauthorized');
    raise EHorseCallbackInterrupted.Create;
  end;

  case GRequireKind of
    2:
      if not LPrincipal.HasRole(GRequiredRole) then
      begin
        ARes.Status(403).Send('Forbidden');
        raise EHorseCallbackInterrupted.Create;
      end;
    3:
      if not LPrincipal.HasScope(GRequiredScope) then
      begin
        ARes.Status(403).Send('Forbidden');
        raise EHorseCallbackInterrupted.Create;
      end;
  end;

  ANext;
end;

{ THorseAuthorize }

class function THorseAuthorize.RequireAuthenticated: THorseCallback;
begin
  GRequireKind := 1;
  Result := AuthorizeProc;
end;

class function THorseAuthorize.RequireRole(const ARole: string): THorseCallback;
begin
  GRequireKind := 2;
  GRequiredRole := ARole;
  Result := AuthorizeProc;
end;

class function THorseAuthorize.RequireScope(const AScope: string): THorseCallback;
begin
  GRequireKind := 3;
  GRequiredScope := AScope;
  Result := AuthorizeProc;
end;

initialization
  GRequireKind := 0;

end.
