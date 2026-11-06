# Swipt + Egern 本机回环设置（iOS 27，无需 Mac / 越狱）

> **注意：这是一份使用说明，不是可导入 Egern 的模块。**
> Egern 目前公开的官方模块格式未列出“虚拟接口回流地址”设置；单纯导入 YAML 模块不能确认会启用回环能力，请在 Egern App 内设置。

## 设置步骤

1. 将 Egern 更新到 **2.21.0 或更新版本**。
2. 在 Egern 的设置中找到 **虚拟接口回流地址**（Virtual Interface Loopback Addresses）。
3. 新增 IPv4 地址 `10.7.0.1`。只填 IP，不要添加 `/32`，除非应用的输入栏明确要求 CIDR。
4. 保存设置，关闭其他回环 VPN（例如 LocalDevVPN）。
5. 断开并重新连接 **Egern VPN**，确保它仍在运行。
6. 连接 Wi-Fi，打开 Swipt，进行本机配对或检查 `Loopback VPN` 是否已识别。

## 注意事项

- 此功能是 Egern 自身的本机回环功能，不需要额外开启 LocalDevVPN。
- 开启回流地址后，Egern 虚拟接口仅使用 **IPv4**，可能影响原本的 IPv6 连接。
- Swipt 的核心开发者服务功能在蜂窝数据环境下存在限制；优先在 Wi-Fi 下测试。
- 这份说明不能保证任意 Swipt Nightly 版本都已实测兼容。
- 不要把 Surge 的 `[IP Rewrite] reflect` 模块直接当成 Egern 模块导入。
- **本仓库其他 Egern 配置、脚本和去广告规则未修改。**

## 参考

- Egern 官方更新公告（2.21.0）：https://t.me/s/egern_news
- Egern 官方模块格式：https://egernapp.com/zh-CN/docs/configuration/modules/
- Swipt 官方源码：https://github.com/swipt-automation/swipt
- Swipt 本机连接地址源码：https://github.com/swipt-automation/swipt/blob/main/internal/coredevice/vpnpeer/vpnpeer.go
