@echo off
rem Compile Java files
echo Compiling Java files...
if not exist "target\classes" mkdir "target\classes"

javac -d target/classes src\main\java\packetanalyzer\*.java
if %ERRORLEVEL% neq 0 (
    echo Compilation failed.
    exit /b %ERRORLEVEL%
)
echo Compilation successful.

rem Get the run mode (first argument)
set RUN_MODE=%1

rem Extract the rest of the arguments to pass to the Java program
for /f "tokens=1,* delims= " %%a in ("%*") do set REST_ARGS=%%b

if "%RUN_MODE%"=="run" (
    echo Running Main...
    java -cp target/classes packetanalyzer.Main %REST_ARGS%
) else if "%RUN_MODE%"=="run-simple" (
    echo Running MainSimple...
    java -cp target/classes packetanalyzer.MainSimple %REST_ARGS%
) else if "%RUN_MODE%"=="run-multi" (
    echo Running MainDpi...
    java -cp target/classes packetanalyzer.MainDpi %REST_ARGS%
) else (
    echo Invalid or missing run mode. Use 'run', 'run-simple', or 'run-multi'.
    exit /b 1
)
