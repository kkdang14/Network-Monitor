@echo off
echo [1] Dang xoa thu muc cu...
if exist dist rmdir /s /q dist
if exist build rmdir /s /q build
if exist "APT_Detector.exe" del "APT_Detector.exe"

echo [2] Dang dong goi bang Nuitka (1 file .exe duy nhat)...
python -m nuitka ^
    --onefile ^
    --windows-icon-from-ico=C:\Users\HP\OneDrive\Document\Dang\CourseFile\Project\APT\APT_APP\icon.ico ^
    --enable-plugin=tk-inter ^
    --output-dir=dist ^
    --windows-disable-console ^
    app.py

echo.
if exist "dist\main.exe" (
    ren "dist\main.exe" "APT_Detector.exe"
    move "dist\APT_Detector.exe" "APT_Detector.exe" >nul
    echo ================================
    echo   XONG! File .exe da tao:
    echo   APT_Detector.exe (~500MB)
    echo   Chay bang quyen Admin!
    echo ================================
) else (
    echo [LOI] Dong goi that bai!
)
pause