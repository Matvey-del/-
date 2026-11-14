# By LainProject — Windows 7 build

## Target
- Windows 7 SP1 (x64 recommended), plus newer Windows versions.
- Build uses Python 3.8.10 and PyInstaller 5.13.2 to retain Windows 7 compatibility.
- The application code uses Python standard-library modules only: tkinter, pathlib, zipfile, ctypes, threading, queue, hashlib, shutil, os, sys, datetime.
- PyInstaller is a build-time dependency only. The user does not need Python installed to run the packaged EXE.

## Build on GitHub
1. Create a GitHub repository.
2. Upload `ByLainProject_scanner.py` to the repository root.
3. Upload `.github/workflows/build.yml` preserving its path.
4. Open Actions → Build By LainProject (Windows 7 compatible) → Run workflow.
5. Download the `ByLainProject-Windows7` artifact after the run succeeds.

## Local build
Install Python 3.8.10, then run:

```bat
py -3.8 -m pip install "pyinstaller==5.13.2"
py -3.8 -m PyInstaller --clean --noconfirm --onefile --windowed --noupx --name ByLainProject ByLainProject_scanner.py
```

The EXE is written to `dist\ByLainProject.exe`.

## Notes
- Build compatibility does not guarantee compatibility on every Windows 7 installation. Test on Windows 7 SP1, and ensure required Windows updates / Universal C Runtime are installed.
- The scanner uses heuristic indicators; it is not an antivirus and can produce false positives.
- Current scan scope is Downloads and Desktop folders of local profiles under `C:\Users`, not the entire C: drive.
- Selected detections are moved to quarantine, not permanently deleted.
