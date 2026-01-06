# Auto Checkin - 自动签到

每天自动登录签到的 GitHub Actions 工作流。

## 功能特性

- ⏰ 每天北京时间 08:00 自动执行
- 🔐 敏感信息通过 GitHub Secrets 安全存储
- 🔄 支持手动触发执行
- 📝 执行日志记录在 GitHub Actions

## 配置指南

### 1. Fork 本仓库

点击右上角 Fork 按钮复制到自己的账户。

### 2. 配置 Secrets

进入仓库 **Settings** → **Secrets and variables** → **Actions** → **New repository secret**

添加以下 Secrets：

| Name | Description |
|------|-------------|
| `USERNAME` | 登录用户名/邮箱 |
| `PASSWORD` | 登录密码 |

### 3. 启用 Actions

1. 进入 **Actions** 选项卡
2. 点击 "I understand my workflows, go ahead and enable them"
3. 选择 **Auto Checkin** 工作流
4. 点击 **Run workflow** 手动测试

## 本地测试

```bash
# 安装依赖
pip install -r requirements.txt

# 设置环境变量并运行
export USERNAME="your_email"
export PASSWORD="your_password"
python src/checkin.py

# 或使用命令行参数
python src/checkin.py -u your_email -p your_password
```

## 执行时间说明

GitHub Actions 使用 UTC 时区，cron 表达式 `0 0 * * *` 表示：
- UTC 时间：每天 00:00
- 北京时间：每天 08:00

> ⚠️ 注意：GitHub Actions 的定时任务可能有几分钟到几十分钟的延迟，这是正常现象。

## 常见问题

### Q: 签到失败怎么办？

1. 检查 Secrets 配置是否正确
2. 查看 Actions 日志确认错误信息
3. 手动触发工作流测试

### Q: 如何修改执行时间？

编辑 `.github/workflows/checkin.yml` 中的 cron 表达式：

```yaml
schedule:
  - cron: '0 0 * * *'  # 修改这里
```

[Cron 表达式在线工具](https://crontab.guru/)

## 免责声明

本项目仅供学习交流使用，请遵守相关网站的服务条款。

## License

MIT
