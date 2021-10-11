program vigereplustea2;

uses
  Forms,
  Unit1 in 'Unit1.pas' {Form1},
  crc32 in 'HASH\crc32.pas',
  DCPsha512 in 'HASH\DCPsha512.pas',
  DCPhaval in 'HASH\DCPhaval.pas',
  DCPcrypt2 in 'HASH\DCPcrypt2.pas',
  DCPconst in 'HASH\DCPconst.pas',
  DCPbase64 in 'HASH\DCPbase64.pas',
  vgt2 in 'vgt2.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.Title := 'VigerePlus TEA II algorithm test';
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
