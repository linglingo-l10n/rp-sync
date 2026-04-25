# rp-sync

> This project was crafted by **gpt-5.4**, **claude-opus-4-6**, and **deepseek-v4-pro**.
> 本项目由 **gpt-5.4**、**claude-opus-4-6** 和 **deepseek-v4-pro** 共同制作。

Simple file synchronization tool that keeps local files in sync with remote artifacts using SHA256 checksum verification.
基于 SHA256 校验和的轻量文件同步工具，保持本地文件与远程制品同步。

## How it works / 工作原理

1. Reads `sync.yaml` from the executable's directory
   从可执行文件所在目录读取 `sync.yaml`
2. For each file, fetches `<url>.sha256` and compares with the local copy
   对每个文件获取 `<url>.sha256` 并与本地文件比对
3. Downloads the file when missing or stale, verifying the checksum after download
   当文件缺失或过期时下载，下载后校验 SHA256

## Configuration / 配置

Create `sync.yaml` next to the binary:
将 `sync.yaml` 放在二进制文件旁：

```yaml
timeout_seconds: 30
user_agent: rp-sync/1.0
files:
  - path: assets/example.txt
    url: https://example.com/example.txt
  - path: data/config.json
    url: https://example.com/config.json
```

| Field / 字段 | Description / 说明 |
| --- | --- |
| `timeout_seconds` | HTTP request timeout, default: 30 / HTTP 请求超时（秒），默认 30 |
| `user_agent` | User-Agent header, default: `rp-sync/1.0` / 请求标识，默认 `rp-sync/1.0` |
| `files[].path` | Relative path to save the file / 保存文件的相对路径 |
| `files[].url` | HTTPS URL to download from / 下载文件的 HTTPS 地址 |

The checksum is fetched from `<url>.sha256` and supports both plain hex and standard `sha256sum` format (`<hash>  <filename>` or `<hash> *<filename>`).
校验和从 `<url>.sha256` 获取，支持纯十六进制和标准 `sha256sum` 两种格式（`<hash>  <filename>` 或 `<hash> *<filename>`）。

## Usage / 用法

```bash
./rp-sync
```

On success, exits 0. On any failure, exits 1 with errors written to stderr and `sync.log`.
成功时退出码为 0，失败时退出码为 1，错误信息输出到 stderr 和 `sync.log`。

## Build / 构建

**Linux / macOS：**

```bash
go build -o rp-sync .
```

**Windows：**

```powershell
go build -o rp-sync.exe .
```
