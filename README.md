# 注意：需要先手动安装xray-core
由于xray-core官方的变化，目前脚本无法成功安装xray，请先按照官方说明手动安装并启动：https://github.com/XTLS/Xray-install/blob/main/alpinelinux/README_zh-Hans.md

# Xray 与 Caddy 自动安装配置脚本

> ⚠️ 重要说明：
> - 本脚本由 AI 辅助生成
> - 主要用于配置 swapchicken.cloud + Cloudflare 的场景
> - 仅支持 VLESS + WebSocket 协议
> - 目前处于测试阶段，尚未经过充分测试
> - 如遇到问题，欢迎在 GitHub 提交 Issue

这是一个用于 Alpine Linux 系统的自动化脚本，用于安装和配置 Xray 代理服务器与 Caddy 网络服务器，实现安全的网络代理服务。

## 功能特点

- 自动安装 Xray 和 Caddy
- 支持 Cloudflare Origin 证书或自签名证书
- 自动配置 VLESS + WebSocket + TLS
- 提供完整的服务管理功能
- 自动生成客户端配置信息
- 内置服务状态监控
- 支持配置修改和更新

## 系统要求

- Alpine Linux 系统
- Root 权限
- 互联网连接
- 域名（可选，但推荐）

## 快速开始

使用以下一行命令直接下载并运行脚本：

```bash
sh <(wget -qO- https://raw.githubusercontent.com/Zhenyi-Wang/swapchicken-xray-caddy-script/main/setup_xray_caddy.sh)
```

## 使用方法

脚本运行后会提供交互式菜单，包含以下选项：

1. **查看配置和服务状态** - 显示当前配置信息和服务运行状态
2. **更改配置** - 修改域名、UUID等配置项
3. **管理Xray服务** - 启动、停止、重启或查看Xray服务状态
4. **管理Caddy服务** - 启动、停止、重启或查看Caddy服务状态
5. **证书管理** - 管理SSL证书（Cloudflare Origin或自签名）
6. **卸载** - 完全卸载Xray和Caddy
7. **退出** - 退出脚本

## 证书选项

脚本支持两种证书配置方式：

1. **Cloudflare Origin 证书** - 适用于使用Cloudflare的域名
2. **自签名证书** - 适用于没有域名或不使用Cloudflare的情况

## 配置文件

- Xray配置文件: `/usr/local/etc/xray/`
- Caddy配置文件: `/etc/caddy/Caddyfile`
- 脚本配置文件: `/etc/xray/config.ini`

## 管理命令

安装完成后，会创建一个管理命令 `xray-manager`，可以随时通过该命令进入管理界面：

```bash
xray-manager
```

## 安全提示

- 请确保更改默认生成的UUID以提高安全性
- 建议使用域名并配置Cloudflare Origin证书
- 定期更新系统和组件以修复安全漏洞

## 故障排除

如果遇到问题，请尝试以下步骤：

1. 检查服务状态：`rc-service xray status` 和 `rc-service caddy status`
2. 查看日志：`cat /var/log/xray/access.log` 和 `cat /var/log/xray/error.log`
3. 确认端口是否开放：`netstat -tulpn | grep xray` 和 `netstat -tulpn | grep caddy`
4. 验证配置文件是否正确

## 卸载

如需卸载，请使用脚本中的卸载选项或运行：

```bash
./setup_xray_caddy.sh uninstall
```

## 许可证

本项目采用 MIT 许可证
