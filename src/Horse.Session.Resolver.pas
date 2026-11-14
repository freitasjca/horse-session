unit Horse.Session.Resolver;

{$IF DEFINED(FPC)}{$MODE DELPHI}{$H+}{$ENDIF}

// =============================================================================
//  horse-session -- principal-resolver contract and chain
//  -----------------------------------------------------------------------------
//  Each credential-extraction scheme (JWT, API key, cookie, mTLS) implements
//  IPrincipalResolver. THorseSession runs them in configured order, first
//  success wins. A resolver that recognises the request shape but fails to
//  authenticate returns False and sets AReason so the audit sink can record
//  the failure; a resolver that doesn't apply to this request (no header /
//  no cookie / no cert) returns False with AReason='' and the chain falls
//  through.
// =============================================================================

interface

uses
{$IF DEFINED(FPC)}
  SysUtils,
{$ELSE}
  System.SysUtils,
{$IFEND}
  Horse.Request,
  Horse.Session.Types;

type
  /// Contract every credential-extraction unit implements.
  ///
  /// Return value semantics:
  ///   Result=True  -> APrincipal is populated (resolver creates the
  ///                   instance, caller takes ownership on return);
  ///                   AReason is ignored.
  ///   Result=False and AReason='' -> this resolver did not recognise the
  ///                   request (no header / no cookie / no cert). The
  ///                   session middleware falls through to the next
  ///                   resolver.
  ///   Result=False and AReason<>'' -> this resolver recognised the request
  ///                   but authentication failed. AReason is a short error
  ///                   code ('invalid-token', 'expired', 'wrong-tenant',
  ///                   etc) suitable for audit; NEVER a raw exception
  ///                   message.
  IPrincipalResolver = interface
    ['{B3E4A7C1-9D52-4F18-A6EC-2F8B5C1A7D40}']
    function TryResolve(const AReq: THorseRequest;
                       out APrincipal: TPrincipal;
                       out AReason: string): Boolean;
    function Name: string;
  end;

implementation

end.
