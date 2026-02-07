#!/bin/bash

set -e

EXT_DIR="/home/bitvision/.config/ghidra/ghidra_12.0.1_PUBLIC/Extensions"
BUILD_DIR="/home/bitvision/GAMES/MSX/GhidraMSX/dist"
TARGET_DIR="$EXT_DIR/GhidraMSX"
GHIDRA_RUN="/home/bitvision/GHIDRA/ghidra_12.0.1_PUBLIC/ghidraRun"

echo "---- Cerrando Ghidra si está en ejecución ----"

# Buscar proceso java que contenga ghidra.GhidraRun
GHIDRA_PID=$(pgrep -f "ghidra.GhidraRun" || true)

if [ -n "$GHIDRA_PID" ]; then
    echo "Matando proceso(s): $GHIDRA_PID"
    kill $GHIDRA_PID
    sleep 2
else
    echo "Ghidra no estaba en ejecución"
fi

# Recompilando
echo "---- Recompilando extensión ----"
/home/bitvision/GAMES/MSX/GhidraMSX/gradlew -p /home/bitvision/GAMES/MSX/GhidraMSX clean buildExtension

echo "---- Eliminando extensión anterior ----"
rm -rf "$TARGET_DIR"

echo "---- Buscando ZIP en dist ----"

ZIP_COUNT=$(ls "$BUILD_DIR"/*.zip 2>/dev/null | wc -l)

if [ "$ZIP_COUNT" -ne 1 ]; then
    echo "ERROR: Se esperaba exactamente 1 ZIP en $BUILD_DIR, encontrados: $ZIP_COUNT"
    exit 1
fi

ZIP_FILE=$(ls "$BUILD_DIR"/*.zip)

echo "ZIP encontrado: $ZIP_FILE"

echo "---- Descomprimiendo ----"
unzip -o "$ZIP_FILE" -d "$EXT_DIR"

echo "---- Arrancando Ghidra ----"
"$GHIDRA_RUN" &

echo "---- Proceso completado ----"


