unit Horse.Session.Authorize;

{$IF DEFINED(FPC)}{$MODE DELPHI}{$H+}{$ENDIF}

// =============================================================================
//  horse-session -- authentication / role / scope checks
//  -----------------------------------------------------------------------------
//  Reads the principal the horse-session middleware attached to the request
//  (PrincipalOf) and fails fast:
//    - no principal, or IsAuthenticated=False -> 401
//    - authenticated but lacking role/scope   -> 403
//  Each refusal is audited as 'authorization.denied' through the sink
//  configured in THorseSession.New, with reason not-authenticated,
//  missing-role or missing-scope.
//
//  Two forms:
//
//    Demand*   Imperative. Call at the top of a route handler. Works on
//              every compiler. On refusal it sends the status and raises
//              EHorseCallbackInterrupted, so the handler stops there.
//
//    Require*  Middleware. RequireAuthenticated carries no state and works
//              everywhere. RequireRole / RequireScope must remember their
//              argument per route, which needs a closure, so they exist on
//              Delphi only. On FPC, THorseCallback is a plain procedure
//              pointer and cannot capture; use DemandRole / DemandScope in
//              the handler instead.
//
//  There is deliberately no shared "required role" variable: two routes with
//  different requirements must never overwrite each other.
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
    class procedure DemandAuthenticated(const AReq: THorseRequest;
                                        const ARes: THorseResponse);
    class procedure DemandRole(const AReq: THorseRequest;
                               const ARes: THorseResponse;
                               const ARole: string);
    class procedure DemandScope(const AReq: THorseRequest;
                                const ARes: THorseResponse;
                                const AScope: string);

    class function RequireAuthenticated: THorseCallback;
{$IF NOT DEFINED(FPC)}
    class function RequireRole(const ARole: string): THorseCallback;
    class function RequireScope(const AScope: string): THorseCallback;
{$IFEND}
  end;

implementation

uses
  Horse.Exception.Interrupted,
  Horse.Session.Audit,
  Horse.Session.Middleware;

procedure Refuse(const AReq: THorseRequest; const ARes: THorseResponse;
                 const APrincipal: TPrincipal; const AStatus: Integer;
                 const ABody, AReason: string);
var
  LTenantId, LUserId: string;
begin
  LTenantId := '';
  LUserId := '';
  if APrincipal <> nil then
  begin
    LTenantId := APrincipal.TenantId;
    LUserId := APrincipal.UserId;
  end;
  HorseSessionAudit(MakeAuthEvent('authorization.denied',
                                  LTenantId, LUserId,
                                  'route', AReq.PathInfo,
                                  'denied', AReason,
                                  AReq.Headers['X-Request-ID']));
  ARes.Status(AStatus).Send(ABody);
  raise EHorseCallbackInterrupted.Create;
end;

procedure AuthenticatedProc(AReq: THorseRequest; ARes: THorseResponse; ANext: TNextProc);
begin
  THorseAuthorize.DemandAuthenticated(AReq, ARes);
  ANext;
end;

{ THorseAuthorize }

class procedure THorseAuthorize.DemandAuthenticated(const AReq: THorseRequest;
                                                    const ARes: THorseResponse);
var
  LPrincipal: TPrincipal;
begin
  LPrincipal := PrincipalOf(AReq);
  if (LPrincipal = nil) or not LPrincipal.IsAuthenticated then
    Refuse(AReq, ARes, LPrincipal, 401, 'Unauthorized', 'not-authenticated');
end;

class procedure THorseAuthorize.DemandRole(const AReq: THorseRequest;
                                           const ARes: THorseResponse;
                                           const ARole: string);
var
  LPrincipal: TPrincipal;
begin
  DemandAuthenticated(AReq, ARes);
  LPrincipal := PrincipalOf(AReq);
  // An empty requirement is a configuration mistake; refuse, never allow.
  if (ARole = '') or not LPrincipal.HasRole(ARole) then
    Refuse(AReq, ARes, LPrincipal, 403, 'Forbidden', 'missing-role');
end;

class procedure THorseAuthorize.DemandScope(const AReq: THorseRequest;
                                            const ARes: THorseResponse;
                                            const AScope: string);
var
  LPrincipal: TPrincipal;
begin
  DemandAuthenticated(AReq, ARes);
  LPrincipal := PrincipalOf(AReq);
  if (AScope = '') or not LPrincipal.HasScope(AScope) then
    Refuse(AReq, ARes, LPrincipal, 403, 'Forbidden', 'missing-scope');
end;

class function THorseAuthorize.RequireAuthenticated: THorseCallback;
begin
  Result := AuthenticatedProc;
end;

{$IF NOT DEFINED(FPC)}
class function THorseAuthorize.RequireRole(const ARole: string): THorseCallback;
var
  LRole: string;
begin
  LRole := ARole;
  Result :=
    procedure(AReq: THorseRequest; ARes: THorseResponse; ANext: TNextProc)
    begin
      THorseAuthorize.DemandRole(AReq, ARes, LRole);
      ANext();
    end;
end;

class function THorseAuthorize.RequireScope(const AScope: string): THorseCallback;
var
  LScope: string;
begin
  LScope := AScope;
  Result :=
    procedure(AReq: THorseRequest; ARes: THorseResponse; ANext: TNextProc)
    begin
      THorseAuthorize.DemandScope(AReq, ARes, LScope);
      ANext();
    end;
end;
{$IFEND}

end.
