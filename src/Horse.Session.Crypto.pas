unit Horse.Session.Crypto;

{$IF DEFINED(FPC)}{$MODE DELPHI}{$H+}{$ENDIF}
{$Q-}{$R-}

// =============================================================================
//  horse-session -- crypto primitives shared by the JWT and cookie resolvers
//  -----------------------------------------------------------------------------
//  SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 2104) in plain Pascal, plus
//  strict base64url (RFC 4648 section 5, no padding) and a constant-time byte
//  compare.
//
//  Why not the RTL: FPC 3.2.2 ships HMAC for MD5 and SHA-1 only, and the
//  Delphi and FPC hash APIs differ. One implementation, validated against
//  the FIPS and RFC 4231 vectors in tests/HorseSessionTests.dpr, gives the
//  same bytes on every compiler with no extra dependency.
//
//  Overflow and range checks are switched off for this unit: SHA-256 relies
//  on 32-bit wrap-around addition.
// =============================================================================

interface

uses
{$IF DEFINED(FPC)}
  SysUtils,
  DateUtils;
{$ELSE}
  System.SysUtils,
  System.DateUtils;
{$IFEND}

const
  /// Smallest HMAC-SHA256 key the resolvers accept, in bytes. RFC 7518
  /// section 3.2 requires a key at least as long as the hash output.
  HORSE_SESSION_MIN_HMAC_KEY_BYTES = 32;

/// SHA-256 digest of AData (32 bytes).
function Sha256(const AData: TBytes): TBytes;
/// HMAC-SHA256 of AData under AKey (32 bytes).
function HmacSha256(const AKey, AData: TBytes): TBytes;
/// True when A and B have the same length and content. Run time depends on
/// the length only, never on where the first difference sits.
function ConstantTimeBytesEqual(const A, B: TBytes): Boolean;

/// base64url without padding.
function Base64UrlEncode(const ABytes: TBytes): string;
/// Strict base64url decode: rejects padding, characters outside the
/// alphabet, impossible lengths and non-zero trailing bits (so one byte
/// string has exactly one accepted encoding).
function Base64UrlDecode(const AText: string; out ABytes: TBytes): Boolean;

/// UTF-8 bytes of S. On FPC the string is taken as already UTF-8.
function Utf8BytesOf(const S: string): TBytes;
/// String from UTF-8 bytes. False when the bytes cannot be decoded.
function Utf8StringOf(const ABytes: TBytes; out S: string): Boolean;
/// One byte per character. For text already known to be 7-bit ASCII.
function AsciiBytesOf(const S: string): TBytes;
/// Lower-case hex.
function BytesToHex(const ABytes: TBytes): string;

/// Seconds since 1970-01-01T00:00:00Z.
function UnixNowUtc: Int64;

implementation

const
  SHA256_K: array[0..63] of Cardinal = (
    $428A2F98, $71374491, $B5C0FBCF, $E9B5DBA5,
    $3956C25B, $59F111F1, $923F82A4, $AB1C5ED5,
    $D807AA98, $12835B01, $243185BE, $550C7DC3,
    $72BE5D74, $80DEB1FE, $9BDC06A7, $C19BF174,
    $E49B69C1, $EFBE4786, $0FC19DC6, $240CA1CC,
    $2DE92C6F, $4A7484AA, $5CB0A9DC, $76F988DA,
    $983E5152, $A831C66D, $B00327C8, $BF597FC7,
    $C6E00BF3, $D5A79147, $06CA6351, $14292967,
    $27B70A85, $2E1B2138, $4D2C6DFC, $53380D13,
    $650A7354, $766A0ABB, $81C2C92E, $92722C85,
    $A2BFE8A1, $A81A664B, $C24B8B70, $C76C51A3,
    $D192E819, $D6990624, $F40E3585, $106AA070,
    $19A4C116, $1E376C08, $2748774C, $34B0BCB5,
    $391C0CB3, $4ED8AA4A, $5B9CCA4F, $682E6FF3,
    $748F82EE, $78A5636F, $84C87814, $8CC70208,
    $90BEFFFA, $A4506CEB, $BEF9A3F7, $C67178F2);

  SHA256_H0: array[0..7] of Cardinal = (
    $6A09E667, $BB67AE85, $3C6EF372, $A54FF53A,
    $510E527F, $9B05688C, $1F83D9AB, $5BE0CD19);

  B64URL_ALPHABET: array[0..63] of Char =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function RotR(const AValue: Cardinal; const ABits: Integer): Cardinal;
begin
  Result := Cardinal(AValue shr ABits) or Cardinal(AValue shl (32 - ABits));
end;

function Sha256(const AData: TBytes): TBytes;
var
  LState: array[0..7] of Cardinal;
  LW: array[0..63] of Cardinal;
  LMsg: TBytes;
  LLen, LPadLen, LOff, I: Integer;
  LBitLen: UInt64;
  LA, LB, LC, LD, LE, LF, LG, LH: Cardinal;
  LS0, LS1, LCh, LMaj, LT1, LT2: Cardinal;
begin
  LLen := Length(AData);

  // Padding: 0x80, zeros, then the bit length as a 64-bit big-endian value,
  // to a multiple of 64 bytes.
  LPadLen := ((LLen + 8) div 64 + 1) * 64;
  LMsg := nil;
  SetLength(LMsg, LPadLen);
  FillChar(LMsg[0], LPadLen, 0);
  if LLen > 0 then
    Move(AData[0], LMsg[0], LLen);
  LMsg[LLen] := $80;
  LBitLen := UInt64(LLen) * 8;
  for I := 0 to 7 do
    LMsg[LPadLen - 1 - I] := Byte((LBitLen shr (8 * I)) and $FF);

  for I := 0 to 7 do
    LState[I] := SHA256_H0[I];

  LOff := 0;
  while LOff < LPadLen do
  begin
    for I := 0 to 15 do
      LW[I] := (Cardinal(LMsg[LOff + I * 4]) shl 24) or
               (Cardinal(LMsg[LOff + I * 4 + 1]) shl 16) or
               (Cardinal(LMsg[LOff + I * 4 + 2]) shl 8) or
               Cardinal(LMsg[LOff + I * 4 + 3]);
    for I := 16 to 63 do
    begin
      LS0 := RotR(LW[I - 15], 7) xor RotR(LW[I - 15], 18) xor (LW[I - 15] shr 3);
      LS1 := RotR(LW[I - 2], 17) xor RotR(LW[I - 2], 19) xor (LW[I - 2] shr 10);
      LW[I] := Cardinal(LW[I - 16] + LS0 + LW[I - 7] + LS1);
    end;

    LA := LState[0]; LB := LState[1]; LC := LState[2]; LD := LState[3];
    LE := LState[4]; LF := LState[5]; LG := LState[6]; LH := LState[7];

    for I := 0 to 63 do
    begin
      LS1 := RotR(LE, 6) xor RotR(LE, 11) xor RotR(LE, 25);
      LCh := (LE and LF) xor ((not LE) and LG);
      LT1 := Cardinal(LH + LS1 + LCh + SHA256_K[I] + LW[I]);
      LS0 := RotR(LA, 2) xor RotR(LA, 13) xor RotR(LA, 22);
      LMaj := (LA and LB) xor (LA and LC) xor (LB and LC);
      LT2 := Cardinal(LS0 + LMaj);
      LH := LG;
      LG := LF;
      LF := LE;
      LE := Cardinal(LD + LT1);
      LD := LC;
      LC := LB;
      LB := LA;
      LA := Cardinal(LT1 + LT2);
    end;

    LState[0] := Cardinal(LState[0] + LA);
    LState[1] := Cardinal(LState[1] + LB);
    LState[2] := Cardinal(LState[2] + LC);
    LState[3] := Cardinal(LState[3] + LD);
    LState[4] := Cardinal(LState[4] + LE);
    LState[5] := Cardinal(LState[5] + LF);
    LState[6] := Cardinal(LState[6] + LG);
    LState[7] := Cardinal(LState[7] + LH);

    Inc(LOff, 64);
  end;

  Result := nil;
  SetLength(Result, 32);
  for I := 0 to 7 do
  begin
    Result[I * 4]     := Byte((LState[I] shr 24) and $FF);
    Result[I * 4 + 1] := Byte((LState[I] shr 16) and $FF);
    Result[I * 4 + 2] := Byte((LState[I] shr 8) and $FF);
    Result[I * 4 + 3] := Byte(LState[I] and $FF);
  end;
end;

function HmacSha256(const AKey, AData: TBytes): TBytes;
var
  LKey: array[0..63] of Byte;
  LHashedKey, LInner, LOuter, LInnerHash: TBytes;
  I: Integer;
begin
  FillChar(LKey, SizeOf(LKey), 0);
  if Length(AKey) > 64 then
  begin
    LHashedKey := Sha256(AKey);
    Move(LHashedKey[0], LKey[0], 32);
  end
  else if Length(AKey) > 0 then
    Move(AKey[0], LKey[0], Length(AKey));

  LInner := nil;
  LOuter := nil;
  SetLength(LInner, 64 + Length(AData));
  SetLength(LOuter, 64 + 32);
  for I := 0 to 63 do
  begin
    LInner[I] := LKey[I] xor $36;
    LOuter[I] := LKey[I] xor $5C;
  end;
  if Length(AData) > 0 then
    Move(AData[0], LInner[64], Length(AData));

  LInnerHash := Sha256(LInner);
  Move(LInnerHash[0], LOuter[64], 32);
  Result := Sha256(LOuter);
end;

function ConstantTimeBytesEqual(const A, B: TBytes): Boolean;
var
  I: Integer;
  LDiff: Byte;
begin
  if Length(A) <> Length(B) then
    Exit(False);
  LDiff := 0;
  for I := 0 to High(A) do
    LDiff := LDiff or (A[I] xor B[I]);
  Result := LDiff = 0;
end;

function Base64UrlEncode(const ABytes: TBytes): string;
var
  LLen, LOutLen, LIn, LOut: Integer;
  LAcc: Cardinal;
begin
  LLen := Length(ABytes);
  LOutLen := (LLen * 4 + 2) div 3;
  Result := '';
  SetLength(Result, LOutLen);
  LIn := 0;
  LOut := 1;
  while LIn + 3 <= LLen do
  begin
    LAcc := (Cardinal(ABytes[LIn]) shl 16) or (Cardinal(ABytes[LIn + 1]) shl 8) or
            Cardinal(ABytes[LIn + 2]);
    Result[LOut]     := B64URL_ALPHABET[(LAcc shr 18) and 63];
    Result[LOut + 1] := B64URL_ALPHABET[(LAcc shr 12) and 63];
    Result[LOut + 2] := B64URL_ALPHABET[(LAcc shr 6) and 63];
    Result[LOut + 3] := B64URL_ALPHABET[LAcc and 63];
    Inc(LIn, 3);
    Inc(LOut, 4);
  end;
  if LLen - LIn = 1 then
  begin
    LAcc := Cardinal(ABytes[LIn]) shl 16;
    Result[LOut]     := B64URL_ALPHABET[(LAcc shr 18) and 63];
    Result[LOut + 1] := B64URL_ALPHABET[(LAcc shr 12) and 63];
  end
  else if LLen - LIn = 2 then
  begin
    LAcc := (Cardinal(ABytes[LIn]) shl 16) or (Cardinal(ABytes[LIn + 1]) shl 8);
    Result[LOut]     := B64URL_ALPHABET[(LAcc shr 18) and 63];
    Result[LOut + 1] := B64URL_ALPHABET[(LAcc shr 12) and 63];
    Result[LOut + 2] := B64URL_ALPHABET[(LAcc shr 6) and 63];
  end;
end;

function Base64UrlValue(const AChar: Char; out AValue: Cardinal): Boolean;
begin
  Result := True;
  case AChar of
    'A'..'Z': AValue := Ord(AChar) - Ord('A');
    'a'..'z': AValue := Ord(AChar) - Ord('a') + 26;
    '0'..'9': AValue := Ord(AChar) - Ord('0') + 52;
    '-':      AValue := 62;
    '_':      AValue := 63;
  else
    AValue := 0;
    Result := False;
  end;
end;

function Base64UrlDecode(const AText: string; out ABytes: TBytes): Boolean;
var
  LLen, LOut, LBits, I: Integer;
  LAcc, LValue: Cardinal;
begin
  ABytes := nil;
  Result := False;
  LLen := Length(AText);
  if LLen mod 4 = 1 then
    Exit;

  SetLength(ABytes, (LLen * 3) div 4);
  LAcc := 0;
  LBits := 0;
  LOut := 0;
  for I := 1 to LLen do
  begin
    if not Base64UrlValue(AText[I], LValue) then
    begin
      ABytes := nil;
      Exit;
    end;
    LAcc := ((LAcc shl 6) or LValue) and $FFFF;
    Inc(LBits, 6);
    if LBits >= 8 then
    begin
      Dec(LBits, 8);
      ABytes[LOut] := Byte((LAcc shr LBits) and $FF);
      Inc(LOut);
    end;
  end;

  // Leftover bits must be zero, otherwise two different texts would decode
  // to the same bytes.
  if (LBits > 0) and ((LAcc and ((Cardinal(1) shl LBits) - 1)) <> 0) then
  begin
    ABytes := nil;
    Exit;
  end;
  Result := True;
end;

function Utf8BytesOf(const S: string): TBytes;
begin
{$IF DEFINED(FPC)}
  Result := nil;
  SetLength(Result, Length(S));
  if Length(S) > 0 then
    Move(S[1], Result[0], Length(S));
{$ELSE}
  Result := TEncoding.UTF8.GetBytes(S);
{$IFEND}
end;

function Utf8StringOf(const ABytes: TBytes; out S: string): Boolean;
begin
  S := '';
  Result := True;
  if Length(ABytes) = 0 then
    Exit;
{$IF DEFINED(FPC)}
  SetLength(S, Length(ABytes));
  Move(ABytes[0], S[1], Length(ABytes));
{$ELSE}
  try
    S := TEncoding.UTF8.GetString(ABytes);
  except
    S := '';
  end;
  Result := S <> '';
{$IFEND}
end;

function AsciiBytesOf(const S: string): TBytes;
var
  I: Integer;
begin
  Result := nil;
  SetLength(Result, Length(S));
  for I := 1 to Length(S) do
    Result[I - 1] := Byte(Ord(S[I]) and $FF);
end;

function BytesToHex(const ABytes: TBytes): string;
const
  HEX_DIGITS: array[0..15] of Char = '0123456789abcdef';
var
  I: Integer;
begin
  Result := '';
  SetLength(Result, Length(ABytes) * 2);
  for I := 0 to High(ABytes) do
  begin
    Result[I * 2 + 1] := HEX_DIGITS[ABytes[I] shr 4];
    Result[I * 2 + 2] := HEX_DIGITS[ABytes[I] and 15];
  end;
end;

function UnixNowUtc: Int64;
begin
{$IF DEFINED(FPC)}
  Result := DateTimeToUnix(LocalTimeToUniversal(Now));
{$ELSE}
  Result := DateTimeToUnix(TTimeZone.Local.ToUniversalTime(Now));
{$IFEND}
end;

end.
