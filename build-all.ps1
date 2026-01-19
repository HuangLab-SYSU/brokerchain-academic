# build-all.ps1
# 在 Windows 上交叉编译 Go 项目为 Windows、Linux、macOS 三个平台，并优化文件大小

$ErrorActionPreference = "Stop"

# 获取当前目录名作为输出二进制文件名（可自定义）
$projectName = "brokerchain_academic"

# 输出目录
$outputDir = "bin"
if (!(Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

# 构建目标平台列表：(GOOS, GOARCH, 后缀)
$targets = @(
    @{ goos = "windows"; goarch = "amd64"; suffix = ".exe" },
    @{ goos = "linux";   goarch = "amd64"; suffix = ""     },
    @{ goos = "darwin";  goarch = "amd64"; suffix = ""     },
    @{ goos = "darwin";   goarch = "arm64"; suffix = "" }
)

Write-Host "🚀 开始构建项目: $projectName" -ForegroundColor Green

foreach ($target in $targets) {
    $env:GOOS = $target.goos
    $env:GOARCH = $target.goarch
    $binName = "$projectName-$($target.goos)-$($target.goarch)$($target.suffix)"
    $outputPath = Join-Path $outputDir $binName

    Write-Host "📦 编译: $binName" -ForegroundColor Cyan
    go build -ldflags="-s -w" -trimpath -o $outputPath .

    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ 编译失败: $binName" -ForegroundColor Red
        exit 1
    }
}

# 清理环境变量
Remove-Item env:GOOS
Remove-Item env:GOARCH

Write-Host "✅ 所有平台构建完成！输出目录: ./$outputDir" -ForegroundColor Green