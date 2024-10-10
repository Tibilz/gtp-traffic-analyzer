#!/bin/bash

# Bereinige vorherige Builds
make clean

# Führe den Build-Prozess aus
make all

# Überprüfe, ob der Build erfolgreich war
if [ $? -eq 0 ]; then
    echo "Build erfolgreich. Starte das Programm..."

    # Führe das Programm aus (ohne Parameter)
    sudo ./build/monitor

    # Falls du das Programm mit "once" ausführen willst, entkommentiere diese Zeile:
    # ./build/monitor once
else
    echo "Build fehlgeschlagen."
fi
