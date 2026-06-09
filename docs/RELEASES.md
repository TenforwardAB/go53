# Release Process for go53

## Automated Releases with GitHub Actions

### How It Works
When you push a git tag starting with `v` (e.g., `v0.77.0`), GitHub Actions automatically:
1. **GoReleaser** builds binaries for all platforms (Linux, macOS, Windows)
2. Both applications are bundled: `go53` (server) and `go53ctl` (CLI tool)
3. Binaries are published on GitHub Releases with checksums

### Release Process

#### 1. Create Version
```bash
./bump_version.sh
# Answer with the new version, e.g., 0.77.0
```

Or manually:
```bash
echo "0.77.0" > VERSION
```

#### 2. Create Git Tag
```bash
git tag -a v0.77.0 -m "Release version 0.77.0"
git push origin v0.77.0
```

Or via `bump_version.sh` (which does everything automatically).

#### 3. GitHub Actions Runs Automatically
- GitHub Actions takes over and builds everything
- You can monitor progress in [Actions](https://github.com/TenforwardAB/go53/actions)
- Binaries are published on the [Releases page](https://github.com/TenforwardAB/go53/releases)

### Download Binaries
After release, binaries are available:
```bash
# Linux x86_64
wget https://github.com/TenforwardAB/go53/releases/download/v0.77.0/go53_0.77.0_linux_amd64.tar.gz

# macOS arm64 (Apple Silicon)
wget https://github.com/TenforwardAB/go53/releases/download/v0.77.0/go53_0.77.0_darwin_arm64.tar.gz

# Windows x86_64
wget https://github.com/TenforwardAB/go53/releases/download/v0.77.0/go53_0.77.0_windows_amd64.zip
```

### Local Testing Before Release
```bash
# Build locally
make build

# Test binaries
./go53 --help
./go53ctl --help
```

### Configuration
- **`.goreleaser.yml`** - Defines which binaries are built and for which platforms
- **`.github/workflows/release.yml`** - GitHub Actions workflow triggered on tags

### Supported Platforms
- **Linux**: amd64, arm64
- **macOS**: amd64, arm64 (Intel & Apple Silicon)
- **Windows**: amd64, arm64

### Checksums
Each release includes `checksums.txt` to verify file integrity:
```bash
sha256sum -c checksums.txt
```
