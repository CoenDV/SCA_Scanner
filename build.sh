#!/usr/bin/env bash
set -euo pipefail

PROJECT="SCAScanner.csproj"
FLAGS="--self-contained true -p:PublishSingleFile=true -p:PublishTrimmed=false -c Release"

echo "Building SCAScanner — self-contained single-file executables"
echo

dotnet publish "$PROJECT" -r osx-arm64 $FLAGS -o publish/osx-arm64
echo

dotnet publish "$PROJECT" -r linux-x64 $FLAGS -o publish/linux-x64
echo

dotnet publish "$PROJECT" -r win-x64   $FLAGS -o publish/win-x64
echo

RELEASE_DIR="publish/release"
mkdir -p "$RELEASE_DIR"

bundle_rid() {
	local rid="$1"
	local src_bin="$2"
	local bundle_name="$3"

	local bundle_dir="$RELEASE_DIR/$bundle_name"
	rm -rf "$bundle_dir"
	mkdir -p "$bundle_dir"

	cp "$src_bin" "$bundle_dir/"

	if [ -d "publish/$rid/Policies" ]; then
		cp -R "publish/$rid/Policies" "$bundle_dir/Policies"
	elif [ -d "Policies" ]; then
		cp -R "Policies" "$bundle_dir/Policies"
	fi

	if [ "$rid" = "win-x64" ] && [ -f "bin/trivy.exe" ]; then
		cp "bin/trivy.exe" "$bundle_dir/trivy.exe"
	fi

	(cd "$bundle_dir" && zip -r "../${bundle_name}.zip" .) >/dev/null
}

bundle_rid "osx-arm64"  "publish/osx-arm64/SCAScanner"    "SCAScanner-osx-arm64"
bundle_rid "linux-x64"  "publish/linux-x64/SCAScanner"    "SCAScanner-linux-x64"
bundle_rid "win-x64"    "publish/win-x64/SCAScanner.exe"  "SCAScanner-win-x64"

echo "Build complete:"
ls -lh "$RELEASE_DIR"/*.zip
