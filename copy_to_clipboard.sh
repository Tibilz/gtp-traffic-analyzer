#!/bin/bash

# Verzeichnis festlegen (Standard ist src/, falls kein Parameter übergeben wurde)
DIR=${1:-src}

# Erstelle eine temporäre Datei für den gesamten Inhalt
TEMP_FILE=$(mktemp)

# Gehe durch jede Datei im angegebenen Verzeichnis
for file in "$DIR"/*; do
    if [ -f "$file" ]; then
        # Dateinamen und Dateiinhalte in die temporäre Datei schreiben
        echo "### Filename: $file ###" >> "$TEMP_FILE"
        cat "$file" >> "$TEMP_FILE"
        echo -e "\n" >> "$TEMP_FILE" # Leerzeile zwischen den Dateien
    fi
done

# Kopiere den Inhalt der temporären Datei in die Zwischenablage (mit pbcopy für macOS)
cat "$TEMP_FILE" | pbcopy

# Entferne die temporäre Datei
rm "$TEMP_FILE"

echo "Der Inhalt aller Dateien im Verzeichnis '$DIR' wurde in die Zwischenablage kopiert."
