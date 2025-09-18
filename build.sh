#!/bin/bash

# Build script for shai-hulud-scanner
# Creates cross-platform binaries

set -e

echo "🔨 Building shai-hulud-scanner for multiple platforms..."

# Clean previous builds
rm -rf bin/
mkdir -p bin/

# Build for different platforms
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
)

for PLATFORM in "${PLATFORMS[@]}"; do
    OS=$(echo $PLATFORM | cut -d'/' -f1)
    ARCH=$(echo $PLATFORM | cut -d'/' -f2)

    BINARY_NAME="scanner-${OS}-${ARCH}"
    if [[ "$OS" == "windows" ]]; then
        BINARY_NAME="${BINARY_NAME}.exe"
    fi

    echo "📦 Building for ${OS}/${ARCH}..."

    # Get version information
    VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "v1.0.0")
    GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Build with version information
    GOOS=$OS GOARCH=$ARCH go build \
        -ldflags="-s -w -X main.Version=${VERSION} -X main.GitCommit=${GIT_COMMIT} -X main.BuildTime=${BUILD_TIME}" \
        -o "bin/${BINARY_NAME}" scanner.go

    # Verify the binary works
    if [[ "$OS" == "windows" ]]; then
        echo "✅ Built bin/${BINARY_NAME}"
    else
        chmod +x "bin/${BINARY_NAME}"
        echo "✅ Built and made executable: bin/${BINARY_NAME}"
    fi
done

echo ""
echo "🎉 Build complete! Binaries created in ./bin/"
echo ""
echo "📋 Available binaries:"
ls -la bin/
echo ""
echo "🚀 Usage examples:"
echo "  ./bin/scanner-linux-amd64 --help"
echo "  ./bin/scanner-macos-arm64 --list-path exploited_packages.txt --root-dir ."
echo ""
echo "📤 Distribution:"
echo "  Copy the appropriate binary for your platform and distribute it."
echo "  No runtime dependencies required!"