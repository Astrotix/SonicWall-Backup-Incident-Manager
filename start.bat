@echo off
echo ========================================
echo Console de Management SonicWall
echo ========================================
echo.
echo Verification de Python...
python --version
if %errorlevel% neq 0 (
    echo ERREUR: Python n'est pas installe ou n'est pas dans le PATH
    echo Telechargez Python depuis https://www.python.org/downloads/
    pause
    exit /b 1
)
echo.
echo Installation des dependances...
echo.
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo.
    echo ERREUR: L'installation des dependances a echoue
    echo Verifiez votre connexion Internet et reessayez
    pause
    exit /b 1
)
echo.
echo ========================================
echo Installation terminee avec succes!
echo ========================================
echo.
echo Demarrage de l'application...
echo.
echo Ouvrez votre navigateur a: http://localhost:5000
echo.
echo Appuyez sur Ctrl+C pour arreter l'application
echo ========================================
echo.
python app.py
pause

