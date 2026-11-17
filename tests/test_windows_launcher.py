"""Compile the launcher with a console harness; never open its GUI or install."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parents[1]
CSC = Path(os.environ.get("WINDIR", "C:/Windows")) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe"

HARNESS = r'''
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
public static class Harness {
    public static int Main(string[] args) {
        Console.OutputEncoding = Setup.Utf8;
        var info = Setup.ProcessInfo(args[0], args.Skip(1).ToArray(), Directory.GetCurrentDirectory());
        using (var child = new Process { StartInfo = info }) {
            child.Start();
            using (var writer = new StreamWriter(child.StandardInput.BaseStream, Setup.Utf8)) {
                writer.WriteLine("{\"input\":\"中文口令仅测试\"}");
            }
            var stdout = child.StandardOutput.ReadToEndAsync();
            var stderr = child.StandardError.ReadToEndAsync();
            if (!child.WaitForExit(30000)) { child.Kill(); return 80; }
            Console.Write(stdout.GetAwaiter().GetResult());
            var errors = stderr.GetAwaiter().GetResult();
            if (errors.Length != 0) { Console.Error.Write(errors); return 81; }
            return child.ExitCode;
        }
    }
}
'''


@pytest.fixture(scope="module")
def launcher_harness(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if os.name != "nt" or not CSC.is_file():
        pytest.skip("Windows .NET Framework compiler required")
    root = tmp_path_factory.mktemp("launcher-中文 编译")
    source = root / "Harness.cs"
    source.write_text(HARNESS, encoding="utf-8-sig")
    executable = root / "Harness.exe"
    result = subprocess.run(
        [str(CSC), "/nologo", "/target:exe", "/platform:x64", "/codepage:65001", "/main:Harness",
         "/r:System.Windows.Forms.dll", "/r:System.Drawing.dll", "/r:System.Web.Extensions.dll",
         "/out:" + str(executable), str(PROJECT / "scripts/windows-installer/Setup.cs"), str(source)],
        capture_output=True, timeout=60, check=False,
    )
    assert result.returncode == 0, result.stdout.decode(errors="replace")
    return executable


def test_csharp_quote_and_utf8_process_roundtrip(launcher_harness: Path, tmp_path: Path,
                                               monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYTHONIOENCODING", "cp936")
    monkeypatch.setenv("PYTHONUTF8", "0")
    script = tmp_path / "中文 空格 $ ' 参数.py"
    script.write_text(
        "import json,os,sys\nprint(json.dumps({'argv':sys.argv[1:],'stdin':json.loads(sys.stdin.buffer.read().decode('utf-8-sig')),"
        "'encoding':sys.stdout.encoding,'pythonioencoding':os.environ['PYTHONIOENCODING']},ensure_ascii=False))\n",
        encoding="utf-8",
    )
    values = ["中文 路径", "", "apostrophe's", "$dollar", "back\\slash\\", 'embedded"quote',
              'spaces \\"quote" \\', str(tmp_path / "目录 有空格")]
    result = subprocess.run([str(launcher_harness), sys.executable, str(script), *values],
                            capture_output=True, timeout=45, check=False)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    data = json.loads(result.stdout.decode("utf-8-sig"))
    assert data["argv"] == values
    assert data["stdin"] == {"input": "中文口令仅测试"}
    assert data["encoding"].lower().replace("-", "") == "utf8"
    assert data["pythonioencoding"] == "utf-8"


@pytest.mark.skipif(os.name != "nt" or not CSC.is_file(), reason="Windows compiler required")
def test_windows_gui_build_smoke_without_running_gui(tmp_path: Path) -> None:
    output = tmp_path / "中文 编译输出"
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-File",
         str(PROJECT / "scripts/windows-installer/build.ps1"), "-OutputDirectory", str(output)],
        capture_output=True, timeout=60, check=False,
    )
    assert result.returncode == 0, result.stdout.decode(errors="replace")
    for name in ("fxfetch-setup.exe", "fxfetch.exe"):
        path = output / name
        assert path.read_bytes().startswith(b"MZ")
        assert path.stat().st_size > 1024
