# Microsoft Developer Studio Project File - Name="cryptest" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=cryptest - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "cryptest.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "cryptest.mak" CFG="cryptest - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "cryptest - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "cryptest - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""$/cryptlib", BAAAAAAA"
# PROP Scc_LocalPath "."
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "cryptest - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "cryptes0"
# PROP BASE Intermediate_Dir "cryptes0"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "CTRelease"
# PROP Intermediate_Dir "CTRelease"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386

!ELSEIF  "$(CFG)" == "cryptest - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "cryptes1"
# PROP BASE Intermediate_Dir "cryptes1"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "CTDebug"
# PROP Intermediate_Dir "CTDebug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept

!ENDIF 

# Begin Target

# Name "cryptest - Win32 Release"
# Name "cryptest - Win32 Debug"
# Begin Group "Data Files"

# PROP Default_Filter ".dat;.txt"
# Begin Source File

SOURCE=.\3desval.dat
# End Source File
# Begin Source File

SOURCE=.\3wayval.dat
# End Source File
# Begin Source File

SOURCE=.\blum1024.dat
# End Source File
# Begin Source File

SOURCE=.\blum2048.dat
# End Source File
# Begin Source File

SOURCE=.\blum512.dat
# End Source File
# Begin Source File

SOURCE=.\castval.dat
# End Source File
# Begin Source File

SOURCE=.\descert.dat
# End Source File
# Begin Source File

SOURCE=.\dh1024.dat
# End Source File
# Begin Source File

SOURCE=.\dh2048.dat
# End Source File
# Begin Source File

SOURCE=.\dh512.dat
# End Source File
# Begin Source File

SOURCE=.\diamond.dat
# End Source File
# Begin Source File

SOURCE=.\dsa1024.dat
# End Source File
# Begin Source File

SOURCE=.\dsa512.dat
# End Source File
# Begin Source File

SOURCE=.\elgc1024.dat
# End Source File
# Begin Source File

SOURCE=.\elgc2048.dat
# End Source File
# Begin Source File

SOURCE=.\elgc512.dat
# End Source File
# Begin Source File

SOURCE=.\gostval.dat
# End Source File
# Begin Source File

SOURCE=.\havalcer.dat
# End Source File
# Begin Source File

SOURCE=.\ideaval.dat
# End Source File
# Begin Source File

SOURCE=.\luc1024.dat
# End Source File
# Begin Source File

SOURCE=.\luc2048.dat
# End Source File
# Begin Source File

SOURCE=.\luc512.dat
# End Source File
# Begin Source File

SOURCE=.\lucc1024.dat
# End Source File
# Begin Source File

SOURCE=.\lucc512.dat
# End Source File
# Begin Source File

SOURCE=.\lucdif.dat
# End Source File
# Begin Source File

SOURCE=.\lucs1024.dat
# End Source File
# Begin Source File

SOURCE=.\lucs512.dat
# End Source File
# Begin Source File

SOURCE=.\marsval.dat
# End Source File
# Begin Source File

SOURCE=.\mqv1024.dat
# End Source File
# Begin Source File

SOURCE=.\mqv2048.dat
# End Source File
# Begin Source File

SOURCE=.\mqv512.dat
# End Source File
# Begin Source File

SOURCE=.\nr1024.dat
# End Source File
# Begin Source File

SOURCE=.\nr2048.dat
# End Source File
# Begin Source File

SOURCE=.\nr512.dat
# End Source File
# Begin Source File

SOURCE=.\rabi1024.dat
# End Source File
# Begin Source File

SOURCE=.\rabi2048.dat
# End Source File
# Begin Source File

SOURCE=.\rabi512.dat
# End Source File
# Begin Source File

SOURCE=.\rc2val.dat
# End Source File
# Begin Source File

SOURCE=.\rc5val.dat
# End Source File
# Begin Source File

SOURCE=.\rc6val.dat
# End Source File
# Begin Source File

SOURCE=.\rijndael.dat
# End Source File
# Begin Source File

SOURCE=.\rsa1024.dat
# End Source File
# Begin Source File

SOURCE=.\rsa2048.dat
# End Source File
# Begin Source File

SOURCE=.\rsa400pb.dat
# End Source File
# Begin Source File

SOURCE=.\rsa400pv.dat
# End Source File
# Begin Source File

SOURCE=.\rsa512.dat
# End Source File
# Begin Source File

SOURCE=.\rsa512a.dat
# End Source File
# Begin Source File

SOURCE=.\rw1024.dat
# End Source File
# Begin Source File

SOURCE=.\rw2048.dat
# End Source File
# Begin Source File

SOURCE=.\rw512.dat
# End Source File
# Begin Source File

SOURCE=.\saferval.dat
# End Source File
# Begin Source File

SOURCE=.\serpentv.dat
# End Source File
# Begin Source File

SOURCE=.\sharkval.dat
# End Source File
# Begin Source File

SOURCE=.\squareva.dat
# End Source File
# Begin Source File

SOURCE=.\twofishv.dat
# End Source File
# Begin Source File

SOURCE=.\usage.dat
# End Source File
# End Group
# Begin Source File

SOURCE=.\bench.cpp
# End Source File
# Begin Source File

SOURCE=.\bench.h
# End Source File
# Begin Source File

SOURCE=.\Makefile
# End Source File
# Begin Source File

SOURCE=.\test.cpp
# End Source File
# Begin Source File

SOURCE=.\validat1.cpp
# End Source File
# Begin Source File

SOURCE=.\validat2.cpp
# End Source File
# Begin Source File

SOURCE=.\validat3.cpp
# End Source File
# Begin Source File

SOURCE=.\validate.h
# End Source File
# End Target
# End Project
