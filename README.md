# Shai-Hulud Scanner (Go Implementation)

A cross-platform security scanner for JavaScript/TypeScript lockfiles, written in Go.

## Usage Examples

```bash
# Basic scan
./scanner --list-path exploited_packages.txt --root-dir .

# Specific managers
./scanner --list-path exploited_packages.txt --managers yarn,npm

# JSON output for CI/CD
./scanner --list-path exploited_packages.txt --json --json-path results.json

# Filtered scanning
./scanner --list-path exploited_packages.txt \
          --include "apps/**,packages/**" \
          --exclude "**/node_modules/**,**/dist/**"
```

## 🔍 Scanning Behavior

**Complete Coverage:**
- ✅ **Direct dependencies** - packages in your package.json
- ✅ **Transitive dependencies** - ALL nested dependencies via lockfiles
- ✅ **All lockfiles** - package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock
- ✅ **Nested projects** - monorepos, workspaces, subdirectories

**Default Exclusions:**
- `**/node_modules/**` - installed packages (see below)
- `**/.pnpm-store/**` - pnpm package store
- `**/dist/**` - build outputs
- `**/build/**` - build directories
- `**/tmp/**` - temporary files
- `**/.turbo/**` - Turborepo cache

**Why exclude node_modules?**
Lockfiles (package-lock.json, yarn.lock, etc.) already contain **ALL** transitive dependency information. Scanning node_modules would:
- 🔴 **Duplicate work** - same packages scanned multiple times
- 🐌 **Performance hit** - 10x+ slower on large projects
- ⚠️ **False positives** - dev dependencies of dependencies
- 🎯 **No additional security** - main lockfile has all transitive deps

For Shai-Hulud protection, scanning main lockfiles gives you complete coverage of all packages that will actually be installed.

## 🚀 Production Deployment

### Using the GitHub Action

Add the scanner to your CI/CD pipeline:

```yaml
- name: Scan for compromised packages
  uses: jpmckearin/shai-hulud-scanner@main
  with:
    list-path: 'security/exploited-packages.txt'
    root-dir: '.'
    managers: 'yarn,npm,pnpm,bun'
    fail-on-match: true
```

### Standalone Binary Usage

1. **Download from Releases**:
   - Go to [Releases](https://github.com/jpmckearin/shai-hulud-scanner/releases)
   - Download the appropriate binary for your platform
   - Make executable: `chmod +x scanner-linux-amd64`

2. **Build from Source**:
   ```bash
   # Clone repository
   git clone https://github.com/jpmckearin/shai-hulud-scanner.git
   cd shai-hulud-scanner

   # Build for your platform
   go build -o scanner scanner.go

   # Or use the build script for all platforms
   chmod +x build.sh
   ./build.sh
   ```

3. **Run the Scanner**:
   ```bash
   ./scanner --list-path exploited_packages.txt --root-dir .
   ```

### Enterprise Integration

For enterprise environments:

- **Private Registries**: Use custom `exploited-packages.txt` files
- **CI/CD Integration**: Integrate into existing pipelines
- **Automated Updates**: Set up automated dependency scanning
- **Custom Rules**: Extend scanner for organization-specific requirements

## 🔧 Development

### Prerequisites

- Go 1.21+ installed

### Build

```bash
go build -o scanner scanner.go
```

### Test

```bash
go test ./...
```

### Cross-Platform Builds

```bash
chmod +x build.sh
./build.sh
```

## 🎯 Why Go?

| Aspect | PowerShell Issues | Go Solution |
|--------|------------------|-------------|
| **Parameter Binding** | Complex splatting, array conflicts | Simple `flag` package |
| **Cross-Platform** | PowerShell Core required | Native binaries |
| **Dependencies** | Runtime required | Self-contained |
| **Performance** | .NET overhead | Native speed |
| **Maintainability** | Complex parameter handling | Clean, typed code |
| **Distribution** | Script files | Single executable |

## 📊 Performance Comparison

| Operation | PowerShell | Go |
|-----------|------------|----|
| Startup Time | ~200-500ms | ~10-50ms |
| Memory Usage | ~50-100MB | ~5-15MB |
| File I/O | .NET overhead | Native system calls |
| String Processing | Complex escaping | Native operations |

## 🔄 Migration Path

If you want to migrate from PowerShell:

1. **Keep the same command-line interface** - users don't need to change
2. **Maintain JSON output format** - CI/CD pipelines unchanged
3. **Preserve all functionality** - same features, better reliability
4. **Gradual rollout** - distribute Go binaries alongside PowerShell scripts

The Go implementation provides the same functionality with dramatically improved reliability and performance!
