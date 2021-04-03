unit uTarget;

{$IF !defined(MSWINDOWS)}
{$MESSAGE ERROR 'This unit is made for Windows only!'}
{$ENDIF MSWindows}
{$IF CompilerVersion >= 23}
{$DEFINE NameSpace}
{$ELSE CompilerVersion}
{$UNDEF NameSpace}
{$IFEND CompilerVersion}

interface

uses
{$IFDEF NameSpace}
  Winapi.Windows, Winapi.TlHelp32, Winapi.PsAPI, Winapi.ShellAPI, Winapi.ShlObj,
  Winapi.ActiveX,
  System.SysUtils, System.Hash, System.Win.ComObj,
  VCL.Graphics;
{$ELSE NameSpace}
  Windows, TlHelp32, PsAPI, ShellAPI, ShlObj, ActiveX,
  SysUtils, ComObj,
  Graphics;
{$ENDIF NameSpace}
{$M+}

type
  /// <summary>This Class helps to handle a Target</summary>
  TTarget = class
  strict private
  class var
    FMemorySet: Byte;
    FMemoryType: Byte;
    FMemoryOffset: Int64;
    FMemoryValue: Int64;
    FHKEY: HKEY;
    function GetPID: DWORD;
    function GetHandle: HWND;
    function GetAuthor: string;
    function GetDescription: string;
{$IFDEF NameSpace}
    function GetHash: string;
{$ENDIF NameSpace}
    function GetFileName: string;
    function GetFileSize: Int64;
    function ReadMem: Int64;
    procedure WriteMem(const Memory: Int64 = 0);
    function GetProcessIcon: TIcon;
    function GetRegistry: string;
    procedure SetRegistry(const Value: string = '');
    function GetReadme: string;
    function GetLocalFileName: string;
    function GetFileVersion: string;
    function GetFileVersion64: Int64;
  private
    /// <summary>Free a PItemIDList</summary>
    procedure FreePidl(pIDL: PItemIDList);
    /// <summary>Returns path to current Desktop</summary>
    function GetDesktopDirectory: String;
    /// <summary>Create a .lnk file by given arguments</summary>
    function MakeALink(const sNewPathAndLinkfilename: String;
      pTargetPathAndFilename, pAddCommandLine, pTargetWorkPath,
      pIconFromExe: PChar; iIconIndex: Integer; pDescription: PChar): Boolean;
  public
    /// <summary>Set used Memory-Info (GHotKey)</summary>
    /// <summary>(begin at 1)</summary>
    class property MemorySet: Byte read FMemorySet write FMemorySet;
    /// <summary>Set used Memory-Type</summary>
    /// <remarks>
    /// <para>Valid Types:</para>
    /// <para>0 = Byte</para>
    /// <para>1 = Word</para>
    /// <para>2 = DWORD</para>
    /// <para>3 = Int64</para>
    /// </remarks>
     class property MemoryType: Byte read FMemoryType write FMemoryType;
    /// <summary>Set Memory Address to work with</summary>
    class property MemoryOffset: Int64 read FMemoryOffset write FMemoryOffset;
    /// <summary>here we store last good value</summary>
    /// <summary>ATM a bit obsolete...</summary>
    class property MemoryValue: Int64 read FMemoryValue write FMemoryValue;
    (*
      /// <summary>Read to Buffer from ProcessID's Memory</summary>
      function _ReadMem(PID: THandle; Address: PUINT; var Buffer: Pointer; Size: Integer): Boolean;
      /// <summary>Write Buffer to ProcessID's Memory</summary>
      function _WriteMem(PID: THandle; Address: PUINT; Buffer: Pointer; var Size: SIZE_T): Boolean;
    *)
    /// <summary>Returns ProcessID by ExeName</summary>
    /// <param name="ExeName">The Executable FileName</param>
    /// <returns>ProcessID</returns>
    function _GetPIDByName(const ExeName: string = ''): Cardinal;
    /// <summary>Returns ProcessID by WindowCaption</summary>
    /// <param name="_Caption">The Window Caption</param>
    /// <returns>ProcessID</returns>
    function _GetPIDByCaption(const _Caption: string = ''): Cardinal;
    /// <summary>Returns Full Path and FileName of ProcessID</summary>
    /// <param name="PID">The ProcessID</param>
    /// <returns>Full Path and FileName of Process Handle</returns>
    function _GetProcessPathFromPID(PID: DWORD = 0): string;
    /// <summary>Returns Full Path and FileName of Process Handle</summary>
    /// <param name="Handle">The Process Handle</param>
    /// <returns>Full Path and FileName of Process Handle</returns>
    function _GetProcessPathFromHandle(const Handle: Integer): String;
    /// <summary>Change Privilege of Handle</summary>
    /// <summary>Handle 0 = current process</summary>
    /// <param name="ProcessHandle">The Process Handle</param>
    /// <param name="Privilege">Wich Privilege</param>
    /// <param name="fEnable">Boolean to enable or disable Privilege</param>
    /// <returns><value>true</value> if the job is successful; <value>false</value> otherwise</returns>
    function _EnablePrivilege(const ProcessHandle: Cardinal = 0;
      const Privilege: string = ''; const fEnable: Boolean = True): Boolean;
    { .$IFDEF DEBUG }
    /// <summary>Returns Username who started the ProcessID</summary>
    function _GetUserNameFromPID(PID: DWORD = 0): string;
    { .$ENDIF DEBUG }
    /// <summary>Returns current logged on Username</summary>
    function _GetLocalUserName: string;
    /// <summary>Read a String from System Registry</summary>
    function _GetRegString(const HKEY: HKEY; const lpSubKey: PChar;
      const lpValueName: PChar): string;
    /// <summary>Write a String to System Registry</summary>
    function _SetRegString(const HKEY: HKEY; const lpSubKey: PChar;
      const lpValueName: PChar; const lpNewValue: PChar): Boolean;
    /// <summary>Create a Desktop Link for Trainer</summary>
    function CreateDesktopLink: Boolean;
    /// <summary>Checks if Notepad is open with Readme</summary>
    function IsReadmeOpen: Boolean;
    /// <summary>Returns Boolean if file is already opened</summary>
    function _IsFileInUse(const fName: TFileName): Boolean;
    /// <summary>needed for _IsAdministrator and _IsElevated</summary>
    function _CheckTokenMembership(TokenHandle: THANDLE; SidToCheck: Pointer;
      var IsMember: BOOL): BOOL; stdcall;
    /// <summary>Return True if current process run as administrator</summary>
    function _IsAdministrator: Boolean;
    /// <summary>Return True if current process run full elevated</summary>
    function _IsElevated: Boolean;
    /// <summary>Return Fileversion of Target in 0.0.0.0 Format</summary>
    function _GetFileVersion(const FileName: string = ''): string;
    /// <summary>Return Fileversion as Int64</summary>
    function _GetFileVersion64(const FileName: string = ''): Int64;
  published
    /// <summary>Initialize the class</summary>
    constructor Create;
    /// <summary>Free the class</summary>
    destructor Destroy; override;
    /// <summary>Get ProcessID of Target ExeName or WindowCaption, 0 = not found</summary>
    property PID: DWORD read GetPID;
    /// <summary>Get Process-Handle of Target WindowCaption, 0 = not found</summary>
    property Handle: HWND read GetHandle;
    /// <summary>Get Name of current active User</summary>
    property CurrentUser: string read _GetLocalUserName;
    /// <summary>Returns uSetup.GAboutAuthor</summary>
    property Author: string read GetAuthor;
    /// <summary>Returns uSetup.GAboutWhat</summary>
    property Description: string read GetDescription;
{$IFDEF NameSpace}
    /// <summary>Returns SHA2/SHA512 Hash</summary>
    property Hash: string read GetHash;
{$ENDIF NameSpace}
    /// <summary>Returns Full Path and FileName</summary>
    property FileName: string read GetFileName;
    /// <summary>Returns FileSize</summary>
    property FileSize: Int64 read GetFileSize;
    /// <summary>Read/Write to/from Buffer from ProcessID's Memory</summary>
    property Memory: Int64 read ReadMem write WriteMem;
    /// <summary>Get Icon from Target Process</summary>
    property Icon: TIcon read GetProcessIcon;
    /// <summary>Read/Write System Registry</summary>
    property Registry: string read GetRegistry write SetRegistry;
    /// <summary>Return Filename of Readme</summary>
    property Readme: string read GetReadme;
    /// <summary>Return full Filename of local Target.exe</summary>
    property LocalFileName: string read GetLocalFileName;
    /// <summary>Return current Elevate status</summary>
    property Elevated: Boolean read _IsElevated;
    /// <summary>Return Fileversion of Target in 0.0.0.0 Format</summary>
    /// <summary>(Major.Minor.Release.Build)</summary>
    property TargetFileVersionString: string read GetFileVersion;
    /// <summary>Return Fileversion as Int64</summary>
    property TargetFileVersionInt64: Int64 read GetFileVersion64;
  end;

implementation

uses
  uSetup;

constructor TTarget.Create;
begin
  inherited;
end;

destructor TTarget.Destroy;
begin
  inherited;
end;

function TTarget.GetProcessIcon: TIcon;
var
  IconID: Word;
begin
  IconID := $0000;
  Result := TIcon.Create();
  Result.Handle := ExtractAssociatedIcon(hInstance, PChar(GetFileName), IconID);
end;

function TTarget._GetPIDByCaption(const _Caption: string): Cardinal;
var
  Win: HWND;
  _PID: DWORD;
begin
  Result := 0;
  if _Caption = '' then
    Exit;
  Win := FindWindow(nil, PChar(_Caption));
  if Win > 0 then
  begin
    GetWindowThreadProcessID(Win, @_PID);
    if ((_PID > 0) and (_GetUserNameFromPID(_PID) = _GetLocalUserName)) then
      Result := _PID;
  end;
end;

function TTarget._GetPIDByName(const ExeName: string): Cardinal;
var
  Process: THANDLE;
  ProcessEntry: TProcessEntry32;
begin
  Result := 0;
  if ExeName = '' then
    Exit;
  ProcessEntry.dwSize := SizeOf(TProcessEntry32);
  Process := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if Process <> INVALID_HANDLE_VALUE then
  begin
    if (Process32First(Process, ProcessEntry)) then
      repeat
        if ((LowerCase(ProcessEntry.szExeFile) = LowerCase(ExeName)) and
          (_GetUserNameFromPID(ProcessEntry.th32ProcessID) = _GetLocalUserName))
        then
        begin
          Result := ProcessEntry.th32ProcessID;
          CloseHandle(Process);
          Exit;
        end;
      until (not Process32Next(Process, ProcessEntry));
    CloseHandle(Process);
  end
  else
    raise Exception.Create(SysErrorMessage(GetLastError));
end;

function TTarget.GetPID: DWORD;
var
  PID: DWORD;
begin
  Result := 0;
  // PID := _GetPIDByCaption(uSetup.GTargetCaption);
  PID := _GetPIDByName(uSetup.GTargetFilename);
  if PID = 0 then
    PID := _GetPIDByCaption(uSetup.GTargetCaption);
  if PID > 0 then
    // if _GetUserNameFromPID(PID) = _GetLocalUserName then
    Result := PID;
end;

function TTarget.GetHandle: HWND;
begin
  Result := FindWindow(nil, uSetup.GTargetCaption);
end;

{$IFDEF NameSpace}

function TTarget.GetHash: string;
var
  HashSHA2: THashSHA2;
begin
  HashSHA2.Create(SHA512);
  Result := HashSHA2.GetHashStringFromFile(GetFileName, SHA512);
  HashSHA2.Reset;
end;
{$ENDIF NameSpace}

function TTarget.GetLocalFileName: string;
var
  found: THANDLE;
  FindData: TWin32FindData;
begin
  Result := '';
  found := FindFirstFile(PChar(uSetup.GTargetFilename), FindData);
  if found = INVALID_HANDLE_VALUE then
    found := FindFirstFile(PChar(IncludeTrailingPathDelimiter(Registry) +
      uSetup.GTargetFilename), FindData);
  if found <> INVALID_HANDLE_VALUE then
    Result := ExpandFileName(FindData.cFileName);
{$IFDEF NameSpace}Winapi.{$ENDIF NameSpace}Windows.FindClose(found);
end;

function TTarget.GetFileName: string;
begin
  Result := _GetProcessPathFromPID(GetPID);
end;

function TTarget.GetFileSize: Int64;
var
  FileHandle: THANDLE;
  Size: LARGE_INTEGER;
begin
  Result := 0;
  FileHandle := CreateFile(PChar(GetFileName), GENERIC_READ, FILE_SHARE_READ,
    nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL or FILE_FLAG_SEQUENTIAL_SCAN, 0);
  if FileHandle <> INVALID_HANDLE_VALUE then
  begin
    try
      Size.LowPart :=
{$IFDEF NameSpace}Winapi.{$ENDIF NameSpace}Windows.GetFileSize(FileHandle,
        @Size.HighPart);
      if (Size.LowPart = $FFFFFFFF) and (GetLastError() <> 0) then
      else
        Result := Size.QuadPart;
    finally
      CloseHandle(FileHandle);
    end;
  end;
end;

function TTarget.GetAuthor: string;
begin
  Result := uSetup.GAboutAuthor;
end;

function TTarget.GetDescription: string;
begin
  Result := uSetup.GAboutWhat;
end;

function TTarget.ReadMem: Int64;
var
  Value0: Byte;
  Value1: Word;
  Value2: DWORD;
  Value3: Int64;
  Len, BytesRead: SIZE_T;
  HND: THANDLE;
  checker: Boolean;
begin
  Result := 0;
  checker := False;
  HND := OpenProcess(PROCESS_ALL_ACCESS, False, PID);
  if HND <> INVALID_HANDLE_VALUE then
  begin
    case MemoryType of
      0:
        begin
          Len := SizeOf(Value0);
          checker := ReadProcessMemory(HND, Pointer(MemoryOffset), Addr(Value0),
            Len, BytesRead);
          if checker then
            Result := Int64(Value0);
        end;
      1:
        begin
          Len := SizeOf(Value1);
          checker := ReadProcessMemory(HND, Pointer(MemoryOffset), Addr(Value1),
            Len, BytesRead);
          if checker then
            Result := Int64(Value1);
        end;
      2:
        begin
          Len := SizeOf(Value2);
          checker := ReadProcessMemory(HND, Pointer(MemoryOffset), Addr(Value2),
            Len, BytesRead);
          if checker then
            Result := Int64(Value2);
        end;
      3:
        begin
          Len := SizeOf(Value3);
          checker := ReadProcessMemory(HND, Pointer(MemoryOffset), Addr(Value3),
            Len, BytesRead);
          if checker then
            Result := Int64(Value3);
        end;
    end;
    CloseHandle(HND);
  end;
  if checker then
    MemoryValue := Result;
end;

procedure TTarget.WriteMem(const Memory: Int64 = 0);
var
  Original, Dummy: DWORD;
  VP: Boolean;
  Len, BytesRead: SIZE_T;
  checker: Boolean;
  HND: THANDLE;
begin
  Len := 0;
  HND := OpenProcess(PROCESS_VM_WRITE or PROCESS_VM_OPERATION, false, PID);
//  HND := OpenProcess(PROCESS_ALL_ACCESS, False, PID);
  if HND <> INVALID_HANDLE_VALUE then
  begin
    case MemoryType of
      0:
        Len := SizeOf(Byte);
      1:
        Len := SizeOf(Word);
      2:
        Len := SizeOf(DWORD);
      3:
        Len := SizeOf(Int64);
    end;
    VP := VirtualProtectEx(HND, Ptr(MemoryOffset), Len,
      PAGE_EXECUTE_READWRITE, Original);
//    checker := WriteProcessMemory(HND, Pointer(MemoryOffset), Addr(Memory), Len,
    checker := WriteProcessMemory(HND, Ptr(MemoryOffset), @Memory, Len,
      BytesRead);
    MemoryValue := Memory;
    Len := BytesRead;
    if (VP and checker) then
      VirtualProtectEx(HND, Ptr(MemoryOffset), Len, Original, Dummy);
    CloseHandle(HND);
  end;
end;

function TTarget._GetProcessPathFromPID(PID: DWORD = 0): string;
var
  ths: THANDLE;
  me32: MODULEENTRY32;
begin
  if PID = 0 then
    PID := GetCurrentProcessId;
  Result := '';
  me32.dwSize := SizeOf(MODULEENTRY32);
  ths := CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
  if ths <> INVALID_HANDLE_VALUE then
  begin
    if Module32First(ths, me32) then
      Result := me32.szExePath;
    CloseHandle(ths);
    ChDir(ExtractFilePath(Result));
  end;
end;

function TTarget._GetProcessPathFromHandle(const Handle: Integer): String;
var
  szExeFile: array [0 .. MAX_PATH - 1] of Char;
  HND: THANDLE;
  PID: Cardinal;
begin
  Result := '';
  if Handle > 0 then
  begin
    GetWindowThreadProcessID(Handle, @PID);
    HND := OpenProcess(PROCESS_ALL_ACCESS, False, PID);
    if HND <> INVALID_HANDLE_VALUE then
    begin
      if GetModuleFileNameEx(HND, 0, szExeFile, SizeOf(szExeFile)) = 0 then
        StrPCopy(szExeFile, '');
      Result := szExeFile;
      CloseHandle(HND);
      ChDir(ExtractFilePath(Result));
    end;
  end;
end;

function TTarget._CheckTokenMembership(TokenHandle: THANDLE;
  SidToCheck: Pointer; var IsMember: BOOL): BOOL; stdcall;
  external advapi32 name 'CheckTokenMembership';

function TTarget._IsAdministrator: Boolean;
var
  psidAdmin: Pointer;
  B: BOOL;
const
  SECURITY_NT_AUTHORITY: TSidIdentifierAuthority = (Value: (0, 0, 0, 0, 0, 5));
  SECURITY_BUILTIN_DOMAIN_RID = $00000020;
  DOMAIN_ALIAS_RID_ADMINS = $00000220;
  SE_GROUP_USE_FOR_DENY_ONLY = $00000010;
begin
  psidAdmin := nil;
  try
    Win32Check(AllocateAndInitializeSid(SECURITY_NT_AUTHORITY, 2,
      SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
      psidAdmin));
    if _CheckTokenMembership(0, psidAdmin, B) then
      Result := B
    else
      Result := False;
  finally
    if psidAdmin <> nil then
      FreeSid(psidAdmin);
  end;
end;

function TTarget._IsElevated: Boolean;
const
  TokenElevation = TTokenInformationClass(20);
type
  TOKEN_ELEVATION = record
    TokenIsElevated: DWORD;
  end;
var
  TokenHandle: THANDLE;
  ResultLength: Cardinal;
  ATokenElevation: TOKEN_ELEVATION;
  HaveToken: Boolean;
begin
  if CheckWin32Version(6, 0) then
  begin
    TokenHandle := 0;
    HaveToken := OpenThreadToken(GetCurrentThread, TOKEN_QUERY, True,
      TokenHandle);
    if (not HaveToken) and (GetLastError = ERROR_NO_TOKEN) then
      HaveToken := OpenProcessToken(GetCurrentProcess, TOKEN_QUERY,
        TokenHandle);
    if HaveToken then
    begin
      try
        ResultLength := 0;
        if GetTokenInformation(TokenHandle, TokenElevation, @ATokenElevation,
          SizeOf(ATokenElevation), ResultLength) then
          Result := ATokenElevation.TokenIsElevated <> 0
        else
          Result := False;
      finally
        CloseHandle(TokenHandle);
      end;
    end
    else
      Result := False;
  end
  else
    Result := _IsAdministrator;
end;

function TTarget._EnablePrivilege(const ProcessHandle: Cardinal = 0;
  const Privilege: string = ''; const fEnable: Boolean = True): Boolean;
const
  PrivNormal: array [0 .. 4] of string = ('SeChangeNotifyPrivilege',
    'SeIncreaseWorkingSetPrivilege', 'SeShutdownPrivilege',
    'SeTimeZonePrivilege', 'SeUndockPrivilege');
  PrivElevate: array [0 .. 18] of string = ('SeBackupPrivilege',
    'SeCreateGlobalPrivilege', 'SeCreatePagefilePrivilege',
    'SeCreateSymbolicLinkPrivilege', 'SeDebugPrivilege',
    'SeDelegateSessionUserImpersonatePrivilege', 'SeImpersonatePrivilege',
    'SeIncreaseBasePriorityPrivilege', 'SeIncreaseQuotaPrivilege',
    'SeLoadDriverPrivilege', 'SeManageVolumePrivilege',
    'SeProfileSingleProcessPrivilege', 'SeRemoteShutdownPrivilege',
    'SeRestorePrivilege', 'SeSecurityPrivilege', 'SeSystemEnvironmentPrivilege',
    'SeSystemProfilePrivilege', 'SeSystemtimePrivilege',
    'SeTakeOwnershipPrivilege');
var
  hToken: THANDLE;
  TokenPriv: TOKEN_PRIVILEGES;
  PrevTokenPriv: TOKEN_PRIVILEGES;
  ReturnLength: Cardinal;
  checker: Boolean;
  B: Byte;
begin
  Result := True;
  // Only for Windows NT/2000/XP and later.
  if not(Win32Platform = VER_PLATFORM_WIN32_NT) then
    Exit;
  Result := False;
  if Privilege = '' then
    Exit;
  // if ((ProcessHandle = 0) and ((Privilege in PrivElevate)) and not Elevated) then Exit;
  checker := False;
  for B := 0 to 18 do
    if PrivElevate[B] = Privilege then
    begin
      checker := True;
      Break;
    end;
  if (checker and ((ProcessHandle = 0) and not Elevated)) then
    Exit(False);
  (*
    if ((ProcessHandle = 0) and ((Privilege = 'SeBackupPrivilege') or
    (Privilege = 'SeCreateGlobalPrivilege') or
    (Privilege = 'SeCreatePagefilePrivilege') or
    (Privilege = 'SeCreateSymbolicLinkPrivilege') or
    (Privilege = 'SeDebugPrivilege') or
    (Privilege = 'SeDelegateSessionUserImpersonatePrivilege') or
    (Privilege = 'SeImpersonatePrivilege') or
    (Privilege = 'SeIncreaseBasePriorityPrivilege') or
    (Privilege = 'SeIncreaseQuotaPrivilege') or
    (Privilege = 'SeLoadDriverPrivilege') or
    (Privilege = 'SeManageVolumePrivilege') or
    (Privilege = 'SeProfileSingleProcessPrivilege') or
    (Privilege = 'SeRemoteShutdownPrivilege') or
    (Privilege = 'SeRestorePrivilege') or (Privilege = 'SeSecurityPrivilege') or
    (Privilege = 'SeSystemEnvironmentPrivilege') or
    (Privilege = 'SeSystemProfilePrivilege') or
    (Privilege = 'SeSystemtimePrivilege') or
    (Privilege = 'SeTakeOwnershipPrivilege')) and not Elevated) then
    Exit;
  *)
  // obtain the processes token
  if ProcessHandle = 0 then
    checker := OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES or
      TOKEN_QUERY, hToken)
  else
    checker := OpenProcessToken(ProcessHandle, TOKEN_ADJUST_PRIVILEGES or
      TOKEN_QUERY, hToken);
  if (checker and OpenProcessToken(GetCurrentProcess(),
    TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, hToken)) then
  begin
    try
      // Get the locally unique identifier (LUID) .
      if LookupPrivilegeValue(nil, PChar(Privilege),
        TokenPriv.Privileges[0].Luid) then
      begin
        TokenPriv.PrivilegeCount := 1; // one privilege to set
        case fEnable of
          True:
            TokenPriv.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
          False:
            TokenPriv.Privileges[0].Attributes := 0;
        end;
        ReturnLength := 0; // replaces a var parameter
        PrevTokenPriv := TokenPriv;
        // enable or disable the privilege
        AdjustTokenPrivileges(hToken, False, TokenPriv, SizeOf(PrevTokenPriv),
          PrevTokenPriv, ReturnLength);
      end;
    finally
      CloseHandle(hToken);
    end;
  end;
  // test the return value of AdjustTokenPrivileges.
  Result := (GetLastError = ERROR_SUCCESS);
  if not Result then
    raise Exception.Create(SysErrorMessage(GetLastError));
end;

(*
  function TTarget._EnablePrivilege(const ProcessHandle: Cardinal = 0;
  const Privilege: string = 'SeDebugPrivilege';
  const fEnable: Boolean = True): Boolean;
  var
  ok: Boolean;
  Token: THandle;
  NewState: TTokenPrivileges;
  Luid: TLargeInteger;
  Return: DWORD;
  begin
  if (GetVersion() > $80000000) then // Win9x does not support Privilege
  Result := True
  else // WinNT
  begin
  if ProcessHandle = 0 then
  ok := OpenProcessToken(GetCurrentProcess(),
  TOKEN_ADJUST_PRIVILEGES, Token)
  else
  ok := OpenProcessToken(ProcessHandle, TOKEN_ADJUST_PRIVILEGES, Token);
  if ok then
  begin
  try
  ok := LookupPrivilegeValue(nil, PChar(Privilege), Luid);
  if ok then
  begin
  NewState.PrivilegeCount := 1;
  NewState.Privileges[0].Luid := Luid;
  if fEnable then
  NewState.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED
  else
  NewState.Privileges[0].Attributes := 0;
  ok := AdjustTokenPrivileges(Token, False, NewState,
  SizeOf(TTokenPrivileges), nil, Return);
  end;
  finally
  CloseHandle(Token);
  end;
  end;
  Result := ok;
  end;
  end;
*)

function TTarget._GetUserNameFromPID(PID: DWORD): string;
var
  hToken: THANDLE;
  cbBuf: Cardinal;
  pUser: PTokenUser;
  snu: SID_NAME_USE;
  ProcessHandle: THANDLE;
  UserSize: DWORD;
  DomainSize: DWORD;
  bSuccess: Boolean;
  User, Domain: string;
begin
  Result := '';
  UserSize := 0;
  DomainSize := 0;
  pUser := nil;
  if PID = 0 then
    PID := GetCurrentProcessId();
  _EnablePrivilege(0, 'SeSecurityPrivilege', True);
  ProcessHandle := OpenProcess(PROCESS_QUERY_INFORMATION, False, PID);
  if ProcessHandle <> INVALID_HANDLE_VALUE then
  begin
    if OpenProcessToken(ProcessHandle, TOKEN_QUERY, hToken) then
    begin
      bSuccess := GetTokenInformation(hToken, TokenUser, nil, 0, cbBuf);
      while (not bSuccess) and (GetLastError = ERROR_INSUFFICIENT_BUFFER) do
      begin
        ReallocMem(pUser, cbBuf);
        bSuccess := GetTokenInformation(hToken, TokenUser, pUser, cbBuf, cbBuf);
      end;
      CloseHandle(hToken);
      if not bSuccess then
        Exit;
      LookupAccountSid(nil, pUser^.User.Sid, nil, UserSize, nil,
        DomainSize, snu);
      if (UserSize <> 0) and (DomainSize <> 0) then
      begin
        SetLength(User, UserSize);
        SetLength(Domain, DomainSize);
        if LookupAccountSid(nil, pUser^.User.Sid, PChar(User), UserSize,
          PChar(Domain), DomainSize, snu) then
        begin
          User := StrPas(PChar(User));
          Domain := StrPas(PChar(Domain));
          Result := User;
        end;
      end;
      if bSuccess then
        FreeMem(pUser);
    end;
    CloseHandle(ProcessHandle);
  end;
end;

(*
  function TTarget._GetUserNameFromPID(PID: DWORD = 0): string;
  type
  _TOKEN_USER = record
  User: TSidAndAttributes;
  end;

  TOKEN_USER = _TOKEN_USER;
  PTOKEN_USER = ^TOKEN_USER;
  var
  hToken: THANDLE;
  cbBuf: Cardinal;
  pToken: PTOKEN_USER;
  // pUser: PTOKEN_USER;
  snu: SID_NAME_USE;
  ProcessHandle: THANDLE;
  UserSize, DomainSize: Cardinal;
  bSuccess: Boolean;
  User, Domain: string;
  begin
  if PID = 0 then
  PID := GetCurrentProcessId();
  Result := '';
  pToken := nil;
  _EnablePrivilege(0, 'SeSecurityPrivilege', True);
  ProcessHandle := OpenProcess(PROCESS_QUERY_INFORMATION, False, PID);
  if ProcessHandle <> INVALID_HANDLE_VALUE then
  begin
  if OpenProcessToken(ProcessHandle, TOKEN_QUERY, hToken) then
  begin
  bSuccess := GetTokenInformation(hToken, TokenUser, nil, 0, cbBuf);
  while (not bSuccess) and (GetLastError = ERROR_INSUFFICIENT_BUFFER) do
  begin
  ReallocMem(pToken, cbBuf);
  bSuccess := GetTokenInformation(hToken, TokenUser, pToken,
  cbBuf, cbBuf);
  end;
  CloseHandle(hToken);
  if not bSuccess then
  Exit;
  LookupAccountSid(nil, pToken^.User.Sid, nil, UserSize, nil,
  DomainSize, snu);
  if (UserSize <> 0) and (DomainSize <> 0) then
  begin
  SetLength(User, UserSize);
  SetLength(Domain, DomainSize);
  if LookupAccountSid(nil, pToken^.User.Sid, PChar(User), UserSize,
  PChar(Domain), DomainSize, snu) then
  begin

  User := String(User); //StrPas(PChar(User));
  //          Domain := StrPas(PChar(Domain));

  Result := User;
  end;
  end;
  end;
  CloseHandle(ProcessHandle);
  end;
  if pToken <> nil then FreeMem(pToken, cbBuf);
  end;
*)

function TTarget._GetLocalUserName: string;
var
  aLength: DWORD;
  aUserName: array [0 .. MAX_PATH - 1] of WideChar;
begin
  aLength := MAX_PATH;
  if GetUserName(@aUserName, aLength) then
    Result := aUserName
  else
    raise Exception.Create(SysErrorMessage(GetLastError));
end;

(*
  function TTarget._GetLocalUserName: string;
  const
  cnMaxUserNameLen = 254;
  var
  dwUserNameLen: DWORD;
  begin
  dwUserNameLen := cnMaxUserNameLen - 1;
  SetLength(Result, cnMaxUserNameLen);
  if GetUserName(PChar(Result), dwUserNameLen) then
  SetLength(Result, dwUserNameLen - 1)
  else
  raise Exception.Create(SysErrorMessage(GetLastError));
  end;
*)

function TTarget.GetRegistry: string;
begin
  Result := _GetRegString(uSetup.GRegRoot, PChar(uSetup.GRegSub),
    PChar(uSetup.GRegKey));
end;

procedure TTarget.SetRegistry(const Value: string = '');
begin
  _SetRegString(uSetup.GRegRoot, PChar(uSetup.GRegSub), PChar(uSetup.GRegKey),
    PChar(Value));
end;

function TTarget._SetRegString(const HKEY: HKEY; const lpSubKey: PChar;
  const lpValueName: PChar; const lpNewValue: PChar): Boolean;
// const Key, ValueName, Value: string; RootKey: DWord = HKEY_CLASSES_ROOT);
var
  Status: Integer;
begin
  { LONG RegCreateKeyEx(
    HKEY hKey,	// handle of an open key
    LPCTSTR lpSubKey,	// address of subkey name
    DWORD Reserved,	// reserved
    LPTSTR lpClass,	// address of class string
    DWORD dwOptions,	// special options flag
    REGSAM samDesired,	// desired security access
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,	// address of key security structure
    PHKEY phkResult,	// address of buffer for opened handle
    LPDWORD lpdwDisposition 	// address of disposition value buffer
    ); }
  // Result := False;
  (*
    Status := RegCreateKeyEx(hKey, PChar(lpSubKey), 0, '',
    REG_OPTION_NON_VOLATILE, REGSAM(KEY_WRITE), nil, FHKEY,
    @Disposition);
  *)
  Status := RegCreateKeyEx(HKEY, lpSubKey, 0, nil, REG_OPTION_NON_VOLATILE,
    KEY_WRITE, nil, FHKEY, nil);
  if Status = 0 then
  begin
    Status := RegSetValueEx(FHKEY, lpValueName, 0, REG_SZ, lpNewValue,
      (Length(lpNewValue) + 1) * SizeOf(WideChar));
    RegCloseKey(FHKEY);
  end;
  if Status <> ERROR_SUCCESS then
    Result := False
  else
    Result := True;
  // if Status <> 0 then raise EOleRegistrationError.CreateRes(@SCreateRegKeyError);
end;

Function TTarget._GetRegString(const HKEY: HKEY; const lpSubKey: PChar;
  const lpValueName: PChar): string;
{
  Valid hKey definitions:
  HKEY_CLASSES_ROOT  HKEY_CURRENT_USER  HKEY_LOCAL_MACHINE  HKEY_USERS  HKEY_PERFORMANCE_DATA  HKEY_CURRENT_CONFIG  HKEY_DYN_DATA

  This small function reads out a string value of a registry key.
  Returns empty string if nothing found.
  Example: AnyString := GetRegString (HKEY_LOCAL_MACHINE, 'SOFTWARE\KONAMI\Yu-Gi-Oh! Power Of Chaos\system', 'InstallDir');
}
var
  lpcbData: Longint;
  lpData: array [0 .. 1024] of Char;
Begin
  Result := '';
  lpcbData := SizeOf(lpData);
  // function RegOpenKeyEx(hKey: HKEY; lpSubKey: LPCWSTR; ulOptions: DWORD; samDesired: REGSAM; var phkResult: HKEY): Longint; stdcall;
  if (RegOpenKeyEx(HKEY, lpSubKey, 0, KEY_READ, FHKEY) = 0) then
    try
      if RegQueryValueEx(FHKEY, lpValueName, nil, nil, @lpData, @lpcbData) = 0
      then
        Result := string(lpData);
    except
    end;
  RegCloseKey(FHKEY);
End;

function TTarget.CreateDesktopLink: Boolean;
var
  dest: string;
begin
  Result := False;
  dest := GetDesktopDirectory;
  if dest[Length(dest)] <> '\' then
    dest := dest + '\';
  dest := dest + ChangeFileExt(ExtractFileName(GetFileName), '') +
    ' Trainer' + '.lnk';
  if FileExists(dest) then
    DeleteFile(dest);
  if MakeALink(dest, PChar(ExtractShortPathName(ParamStr(0))), PChar(''),
    PChar(ExcludeTrailingPathDelimiter(ExtractFilePath(GetFileName))),
    PChar(GetFileName), 0, PChar(uSetup.GAboutAuthor + '''s' + ' ' + 'Trainer' +
    ' ' + 'vs' + ' ' + uSetup.GAboutWhat + ' ' + 'v' + uSetup.GTargetVersion))
  then
    Result := True;
end;

procedure TTarget.FreePidl(pIDL: PItemIDList);
var
  Allocator: IMalloc;
begin
  if Succeeded(SHGetMalloc(Allocator)) then
  begin
    Allocator.Free(pIDL);
{$IFDEF VER100}
    Allocator.Release;
{$ENDIF VER100}
  end;
end;

(*
  var
  FavPath: array[0..MAX_PATH] of Char;
  pIDL   : PItemIDList;
  begin
  if Succeeded(ShGetSpecialFolderLocation(Handle, CSIDL_FAVORITES, pIDL)) then begin
  if ShGetPathfromIDList(pIDL, FavPath) then
  ListBox1.Items := GetIEFavourites(StrPas(FavPath));
  // We are responsible for freeing the PItemIDList pointer with the
  // Shell's IMalloc interface
  FreePIDL(pIDL);
  end;
  end;
*)
function TTarget.GetDesktopDirectory: String;
var
  pIDL: PItemIDList;
  InFolder: array [0 .. MAX_PATH] of Char;
begin
  if Succeeded(SHGetSpecialFolderLocation(0, CSIDL_DESKTOPDIRECTORY, pIDL)) then
  begin
    if SHGetPathFromIDList(pIDL, InFolder) then
      Result := StrPas(InFolder)
    else
      Result := '';
    FreePidl(pIDL);
  end;
end;

function TTarget.MakeALink(const sNewPathAndLinkfilename: String;
  pTargetPathAndFilename, pAddCommandLine, pTargetWorkPath, pIconFromExe: PChar;
  iIconIndex: Integer; pDescription: PChar): Boolean;
// Create the shortcut named in the LinkFileName argument, and load its data from the non-nil arguments. Return True if successful.
// small bug/feature shortpathnames are auto-expanded to long file format using quotes.
// how to:
// MakeALink ( 'sNewPathAndLinkfilename.lnk', pChar('pTargetPathAndFilename'), pChar('pAddCommandLine'), pChar('TargetWorkPath'), pChar(pIconFromExe), iIconIndex, pChar('pDescription'))
// where 'sNewPathAndLinkfilename.lnk' = Drive:\Path\to\Filename.lnk - file that we create
// 'pTargetPathAndFilename' = Drive:\Path\to\Source.ext - file that the link will be linked to
// 'pAddCommandLine' = '' - any additional Command Line Flags
// 'TargetWorkPath' = can be empty or a specific path
// 'pIconFromExe' = FileName that contain Icon (.ico/.exe./.dll etc)
// 'iIconIndex' = 0 for first Icon inside 'pIconFromExe'
// 'pDescription' = optional Description, will displayed as a hint
VAR
  vUNK: IUnknown;
  vISL: IShellLink;
  vIPF: IPersistFile;
  fNameW: ARRAY [0 .. MAX_PATH] OF WideChar;
begin
  Result := False;
  try
    StringToWideChar(sNewPathAndLinkfilename, fNameW, MAX_PATH);
    vUNK := CreateComObject(CLSID_ShellLink);
    vISL := vUNK AS IShellLink;
    vIPF := vUNK AS IPersistFile;
    IF pTargetPathAndFilename <> nil THEN
      IF vISL.SetPath(pTargetPathAndFilename) <> S_OK THEN
        Exit;
    IF pAddCommandLine <> nil THEN
      IF vISL.SetArguments(pAddCommandLine) <> S_OK THEN
        Exit;
    IF (pIconFromExe <> nil) THEN
      IF vISL.SetIconLocation(pIconFromExe, iIconIndex) <> S_OK THEN
        Exit;
    IF pTargetWorkPath <> nil THEN
      IF vISL.SetWorkingDirectory(pTargetWorkPath) <> S_OK THEN
        Exit;
    IF pDescription <> nil THEN
      IF vISL.SetDescription(pDescription) <> S_OK THEN
        Exit;
    IF vIPF.Save(@fNameW, False) <> S_OK THEN
      Exit;
    Result := True;
    vIPF := nil;
    vISL := nil;
    vUNK := nil;
  except
    ON Exception DO;
  end;
end;

function TTarget._IsFileInUse(const fName: TFileName): Boolean;
var
  HFileRes: HFILE;
begin
  HFileRes := CreateFile(PChar(fName), GENERIC_READ or GENERIC_WRITE, 0, nil,
    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
  Result := (HFileRes = INVALID_HANDLE_VALUE);
  if not Result then
    CloseHandle(HFileRes);
end;

function TTarget.IsReadmeOpen: Boolean;
var
  s: string;
  Buffer: array [0 .. 255] of Char;
  HWND: Cardinal;
begin
  // below is my try to determine if notepad is running with opened readme file
  // this approach does not care about wich language target os is
  // FYI, target os language result in different a window caption
  Result := False;
  if ((Length(Readme) > 0) and (FindWindow('Notepad', nil) <> 0)) then
  begin
    HWND := GetWindow(FindWindow('Notepad', nil), GW_HWNDFIRST);
    while HWND <> 0 do
    begin
      GetClassName(HWND, Buffer, SizeOf(Buffer));
      s := string(Buffer);
      if LowerCase(s) = LowerCase('Notepad') then
      begin
        GetWindowText(HWND, Buffer, SizeOf(Buffer));
        s := string(Buffer);
        if Pos(LowerCase(ChangeFileExt(ExtractFileName(Readme), '')),
          LowerCase(s)) <> 0 then
        begin
          Result := False;
          Break;
        end;
      end;
      HWND := GetNextWindow(HWND, GW_HWNDNEXT);
    end;
  end
  else
    Result := (Length(Readme) > 0);
end;

function TTarget.GetReadme: string;
var
  FileHandle: THANDLE;
  Size: LARGE_INTEGER;
  FileName: string;
begin
  Result := '';
  // 1st: try get readme from trainers folder
  FileName := ChangeFileExt(ParamStr(0), '.txt');
  FileHandle := CreateFile(PChar(FileName), GENERIC_READ, FILE_SHARE_READ, nil,
    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL or FILE_FLAG_SEQUENTIAL_SCAN, 0);
  if FileHandle = INVALID_HANDLE_VALUE then
  begin
    FileName := ChangeFileExt(ExtractFileName(ParamStr(0)), '.txt');
    FileHandle := CreateFile(PChar(FileName), GENERIC_READ, FILE_SHARE_READ,
      nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL or
      FILE_FLAG_SEQUENTIAL_SCAN, 0);
  end;
  if FileHandle = INVALID_HANDLE_VALUE then
  begin
    FileName := IncludeTrailingPathDelimiter(ExtractFilePath(GetFileName)) +
      ChangeFileExt(ExtractFileName(ParamStr(0)), '.txt');
    FileHandle := CreateFile(PChar(FileName), GENERIC_READ, FILE_SHARE_READ,
      nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL or
      FILE_FLAG_SEQUENTIAL_SCAN, 0);
  end;
  if FileHandle <> INVALID_HANDLE_VALUE then
  begin
    try
      Size.LowPart :=
{$IFDEF NameSpace}Winapi.{$ENDIF NameSpace}Windows.GetFileSize(FileHandle,
        @Size.HighPart);
      if (Size.LowPart = $FFFFFFFF) and (GetLastError() <> 0) then
      else if Size.QuadPart > 0 then
        Result := FileName;
    finally
      CloseHandle(FileHandle);
    end;
  end;
end;

function TTarget.GetFileVersion: string;
begin
  Result := _GetFileVersion(GetFileName);
end;

function TTarget.GetFileVersion64: Int64;
begin
  Result := _GetFileVersion64(GetFileName);
end;

function TTarget._GetFileVersion(const FileName: string = ''): string;
var
  iVerInfoSize, iVerValueSize, iDummy: DWORD;
  pVerInfo: Pointer;
  rVerValue: PVSFixedFileInfo;
  FMajor, FMinor, FRelease, FBuild: Word;
begin
  Result := '';
  if FileName = '' then
    Exit;
  FMajor := 0;
  FMinor := 0;
  FRelease := 0;
  FBuild := 0;
  iVerInfoSize := GetFileVersionInfoSize(PChar(FileName), iDummy);
  if iVerInfoSize > 0 then
  begin
    GetMem(pVerInfo, iVerInfoSize);
    try
      GetFileVersionInfo(PChar(FileName), 0, iVerInfoSize, pVerInfo);
      VerQueryValue(pVerInfo, '\', Pointer(rVerValue), iVerValueSize);
      with rVerValue^ do
      begin
        FMajor := dwFileVersionMS shr 16;
        FMinor := dwFileVersionMS and $FFFF;
        FRelease := dwFileVersionLS shr 16;
        FBuild := dwFileVersionLS and $FFFF;
      end;
    finally
      FreeMem(pVerInfo, iVerInfoSize);
      Result := IntToStr(FMajor) + '.' + IntToStr(FMinor) + '.' +
        IntToStr(FRelease) + '.' + IntToStr(FBuild);
    end;
  end;
end;

function TTarget._GetFileVersion64(const FileName: string = ''): Int64;
var
  iVerInfoSize, iVerValueSize, iDummy: DWORD;
  pVerInfo: Pointer;
  rVerValue: PVSFixedFileInfo;
  FMajor, FMinor, FRelease, FBuild: Word;
  iResult: Int64;
begin
  Result := 0;
  if FileName = '' then
    Exit;
  FMajor := 0;
  FMinor := 0;
  FRelease := 0;
  FBuild := 0;
  iVerInfoSize := GetFileVersionInfoSize(PChar(FileName), iDummy);
  if iVerInfoSize > 0 then
  begin
    GetMem(pVerInfo, iVerInfoSize);
    try
      GetFileVersionInfo(PChar(FileName), 0, iVerInfoSize, pVerInfo);
      VerQueryValue(pVerInfo, '\', Pointer(rVerValue), iVerValueSize);
      with rVerValue^ do
      begin
        FMajor := dwFileVersionMS shr 16;
        FMinor := dwFileVersionMS and $FFFF;
        FRelease := dwFileVersionLS shr 16;
        FBuild := dwFileVersionLS and $FFFF;
      end;
    finally
      FreeMem(pVerInfo, iVerInfoSize);
      iResult := FMajor;
      iResult := (iResult shl 16) + FMinor;
      iResult := (iResult shl 16) + FRelease;
      iResult := (iResult shl 16) + FBuild;
      Result := iResult;
    end;
  end;
end;

end.
