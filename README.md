<p align="center">
  <img src="assets/logo.png" width="180" />
</p>

<h1 align="center">朱雀 Zhuque</h1>

<p align="center">
  腾讯朱雀 AI 检测 CLI — 文本/图片查重, 批量串行, 自动冷却
</p>

<p align="center">
  <a href="README_EN.md">English</a> | 中文
</p>

---

## 安装

```bash
# 需要 Python 3.10+, uv, Node.js (jsdom)
uv tool install git+https://github.com/Sophomoresty/zhuque.git
```

安装后即可使用 `zhuque` 命令。

## 使用

```bash
# 文字检测 (内联)
zhuque check "你的文本内容, 至少200字..."

# 文字检测 (文件)
zhuque check --file article.txt

# 图片检测
zhuque check --image photo.png

# 批量图片
zhuque check --image-dir ./pictures

# 批量检测 (文件列表, 每行一个路径)
zhuque batch manifest.txt

# 验证环境
zhuque doctor
```

## 输出

JSON 格式直出:

```json
{
  "ok": true,
  "type": "text",
  "confidence": 1.0,
  "labels_ratio": {"0": 0.0, "1": 1.0, "2": 0.0},
  "segment_labels": [{"text": "...", "label": 1, "conf": 0.9997}],
  "availableUses": 4
}
```

字段说明:
- `confidence` — AI 生成置信度 (0-1)
- `labels_ratio` — 0=真人, 1=AI生成, 2=不确定
- `segment_labels` — 分段判定
- `ai_generated` — 图片 AI 生成概率 (0-1)

## 限制

- 文本最少 200 字
- 单 IP 实测数据 (5 秒间隔):
  - 连续 ~18 次后触发风控 (evil_level=100)
  - 冷却时间约 30 分钟
  - 单 IP 每小时约 36 次, 每天约 **785 次**
- 批量模式内置自动节流 + 冷却, 无需手动干预
- 如需更高吞吐, 配合代理池使用 (N 个出口 IP × 785 = N × 785 次/天)

## 依赖

- Python 3.10+
- Node.js (用于 TDC captcha 协议)
- jsdom (`npm install -g jsdom` 或项目内安装)

## License

MIT

---

## 致谢

本项目的开发 agent 能力由 [GenericAgent](https://github.com/lsdefine/GenericAgent) 提供。

### 🚩 友情链接

[![GenericAgent](https://img.shields.io/badge/Agent_Framework-GenericAgent-orange?style=for-the-badge&logo=github)](https://github.com/lsdefine/GenericAgent)
[![LinuxDo](https://img.shields.io/badge/社区-LinuxDo-blue?style=for-the-badge)](https://linux.do/)

**同作者其他项目**:

- [bpc-fetch](https://github.com/Sophomoresty/bpc-fetch) — 付费墙绕过, 936 站批量抓取文章
- [gemini-web2api](https://github.com/Sophomoresty/gemini-web2api) — Google Gemini 网页版转 OpenAI 兼容 API
- [qmdec](https://github.com/Sophomoresty/qmdec) — QQ 音乐加密文件解密 + 自动打标签
- [doifans-dl](https://github.com/Sophomoresty/doifans-dl) — DoiFans 付费墙视频下载
