<p align="center">
  <img src="assets/logo.png" width="180" />
</p>

<h1 align="center">Zhuque (朱雀)</h1>

<p align="center">
  Tencent Zhuque AI-generated content detection CLI — text & image, batch serial, auto-cooldown
</p>

<p align="center">
  English | <a href="README.md">中文</a>
</p>

---

## Install

```bash
# Requires Python 3.10+, uv, Node.js (jsdom)
uv tool install git+https://github.com/Sophomoresty/zhuque.git
```

## Usage

```bash
# Text detection (inline)
zhuque check "Your text content, at least 200 characters..."

# Text detection (file)
zhuque check --file article.txt

# Image detection
zhuque check --image photo.png

# Batch images from directory
zhuque check --image-dir ./pictures

# Batch from manifest (one file path per line)
zhuque batch manifest.txt

# Verify environment
zhuque doctor
```

## Output

Clean JSON to stdout:

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

Fields:
- `confidence` — AI-generated confidence (0-1)
- `labels_ratio` — 0=human, 1=AI-generated, 2=uncertain
- `segment_labels` — per-segment analysis
- `ai_generated` — image AI generation probability (0-1)

## Rate Limits

- Text minimum 200 characters
- ~18 requests per burst, then 30 min cooldown (auto-handled)
- Batch mode throttles automatically

## Requirements

- Python 3.10+
- Node.js (for TDC captcha protocol)
- jsdom (`npm install -g jsdom`)

## License

MIT
