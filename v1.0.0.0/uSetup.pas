unit uSetup;

(*

  ********************************************************************************
  ***   In here you setup everything thats needed to make trainer work sweet   ***
  ********************************************************************************

*)

{$IFNDEF MSWindows}
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
  Winapi.Windows;
{$ELSE NameSpace}
  Windows;
{$ENDIF NameSpace}

const
  // this is trainers classname
  GUniqueClassName = 'YGO_POC_JTP16';

  // about info
  GAboutAuthor = 'KodeZwerg';
  GAboutWhat = 'Yu-Gi-Oh! Joey the Passion';

  // target info
  GTargetCaption = 'Yu-Gi-Oh! Power of Chaos';
  GTargetFilename = 'joey_pc.exe';
  GTargetVersion = '1.6';
  GTargetFileSize = 3919872;
  // GTargetCRC       = 'B33734420D4194FA';
  GTargetCRC =
    '3c77b87b7ab591a0e6163cf512dbc4368d8638b3cd434c05449a0df3aae4b5c72133357a1a9e1007bb6e4227445eb44d20396bad5737844e799d2cdbcb91eb62';

  // memory info
  (*
    GMemMode switches (must match the GMemValue Array type!)
    0: Byte;
    1: Word;
    2: DWORD;
    3: Int64;
  *)
  GHotKeys = 2;
  // hotkey 1
  GMemName1 = '(NUMPAD-1) Freeze KI';
  GMemPatches1 = 1;
  GMemOffsets1: ARRAY [1 .. GMemPatches1] of Int64 = ($A55D64);
  GMemValues1: ARRAY [1 .. GMemPatches1] of Word = ($0000);
  GMemMode1 = 1;
  // hotkey 2
  GMemName2 = '(NUMPAD-2) Freeze User';
  GMemPatches2 = 1;
  GMemOffsets2: ARRAY [1 .. GMemPatches2] of Int64 = ($A56AA8);
  GMemValues2: ARRAY [1 .. GMemPatches2] of Word = ($FFFF);
  GMemMode2 = 1;

  // registry info
  GUseReg = True;
  GRegRoot = HKEY_LOCAL_MACHINE;
  GRegSub = 'SOFTWARE\KONAMI\Yu-Gi-Oh! Power Of Chaos\common\';
  GRegKey = 'InstallDir';
  GRegHint =
    'Warning! If you have Yugi the Destiny installed, that should be used!';

  // FileVersion support
  GUseVersion = False;
  GVersion64 = 0;

implementation

end.
