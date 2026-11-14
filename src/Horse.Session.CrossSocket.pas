unit Horse.Session.CrossSocket;

{$IF DEFINED(FPC)}{$MODE DELPHI}{$H+}{$ENDIF}

// =============================================================================
//  horse-session -- CrossSocket mTLS adapter (OPT-IN)
//  -----------------------------------------------------------------------------
//  This unit is NOT referenced by the core horse-session package. Users add it
//  to their application's uses clause to activate mTLS peer-cert extraction on
//  the CrossSocket provider.
//
//    uses
//      Horse,
//      Horse.Session,
//      Horse.Session.MTLS,
//      Horse.Session.CrossSocket;  // <-- activates the extension
//
//  How it works:
//    - At request setup time, the CrossSocket adapter registers an
//      IHorseTLSPeerCert accessor on Req.Services that reads the verified
//      peer certificate from TCrossConnection's underlying TSslContext.
//    - The TMTLSResolver in Horse.Session.MTLS finds the extension, reads
//      the subject fields, and produces a TPrincipal.
//
//  Provider adapters for nghttp2, mORMot and ICS live in their own repos.
//  All implement IHorseTLSPeerCert against their respective TLS surfaces;
//  horse-session itself only ships the contract and the CrossSocket adapter.
//
//  SCAFFOLD NOTE: the actual hook into CrossSocket's request bridge is a TODO
//  until the provider surfaces the peer-cert slot. The contract and the
//  wiring shape are in place; filling in ConnectHook against
//  horse-provider-crosssocket is the only remaining work.
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
  Horse.Session.MTLS;

type
  /// Concrete adapter. Instantiated once per request by the provider hook;
  /// kept alive via interface-reference by Req.Services.
  TCrossSocketPeerCertAdapter = class(TInterfacedObject, IHorseTLSPeerCert)
  strict private
    FIsVerified: Boolean;
    FSubjectCN: string;
    FSubjectO: string;
    FSubjectDN: string;
    FSubjectAltNames: TArray<string>;
    FSerialHex: string;
  public
    constructor Create(const AIsVerified: Boolean;
                       const ASubjectCN, ASubjectO, ASubjectDN, ASerialHex: string;
                       const ASubjectAltNames: TArray<string>);
    function IsVerified: Boolean;
    function SubjectCN: string;
    function SubjectO: string;
    function SubjectDN: string;
    function SubjectAltNames: TArray<string>;
    function SerialHex: string;
  end;

/// Called once at application startup. Hooks into horse-provider-crosssocket
/// so every request carrying a verified peer certificate publishes a
/// TCrossSocketPeerCertAdapter on Req.Services.
///
/// SCAFFOLD: currently a no-op stub. The real implementation registers a
/// callback on TCrossSocketBridge's per-request setup.
procedure RegisterCrossSocketPeerCertAdapter;

implementation

{ TCrossSocketPeerCertAdapter }

constructor TCrossSocketPeerCertAdapter.Create(const AIsVerified: Boolean;
                                               const ASubjectCN, ASubjectO,
                                               ASubjectDN, ASerialHex: string;
                                               const ASubjectAltNames: TArray<string>);
begin
  inherited Create;
  FIsVerified := AIsVerified;
  FSubjectCN := ASubjectCN;
  FSubjectO := ASubjectO;
  FSubjectDN := ASubjectDN;
  FSerialHex := ASerialHex;
  FSubjectAltNames := ASubjectAltNames;
end;

function TCrossSocketPeerCertAdapter.IsVerified: Boolean;
begin
  Result := FIsVerified;
end;

function TCrossSocketPeerCertAdapter.SubjectCN: string;
begin
  Result := FSubjectCN;
end;

function TCrossSocketPeerCertAdapter.SubjectO: string;
begin
  Result := FSubjectO;
end;

function TCrossSocketPeerCertAdapter.SubjectDN: string;
begin
  Result := FSubjectDN;
end;

function TCrossSocketPeerCertAdapter.SubjectAltNames: TArray<string>;
begin
  Result := FSubjectAltNames;
end;

function TCrossSocketPeerCertAdapter.SerialHex: string;
begin
  Result := FSerialHex;
end;

procedure RegisterCrossSocketPeerCertAdapter;
begin
  // TODO: hook into horse-provider-crosssocket. The provider's request
  // bridge publishes TCrossSocketPeerCertAdapter on Req.Services for every
  // request whose connection carries a verified peer cert. See
  // Delphi-Cross-Socket's TCrossConnection for the SSL/TLS handle.
end;

initialization
  RegisterCrossSocketPeerCertAdapter;

end.
