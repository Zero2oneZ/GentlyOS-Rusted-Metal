#!/usr/bin/env python3
"""Download MiniMax-M2.1 and convert to Living SVG Agent"""

import os
os.environ["HF_TOKEN"] = "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"

from huggingface_hub import snapshot_download, login
from pathlib import Path
import hashlib
import json
from datetime import datetime

# Login
login(token=os.environ["HF_TOKEN"])

print("Downloading MiniMax-M2.1...")
print("This is 456B params - gonna take a while...\n")

# Download
model_path = snapshot_download(
    "MiniMaxAI/MiniMax-M2.1",
    token=os.environ["HF_TOKEN"],
    resume_download=True,
)

print(f"\n✓ Downloaded to: {model_path}")

# Now hash and create agent
model_path = Path(model_path)

def hash_file(path):
    h = hashlib.sha256()
    size = path.stat().st_size
    done = 0
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192*1024), b''):  # 8MB chunks
            h.update(chunk)
            done += len(chunk)
            pct = (done / size) * 100
            print(f"\r  Hashing {path.name}: {pct:.1f}%", end='', flush=True)
    print()
    return h.hexdigest()

# Scan files
shards = {}
config = {}

config_path = model_path / "config.json"
if config_path.exists():
    config = json.loads(config_path.read_text())

print("\nHashing weight files...")
for f in sorted(model_path.glob("*.safetensors")):
    shards[f.name] = hash_file(f)

for f in sorted(model_path.glob("*.bin")):
    shards[f.name] = hash_file(f)

for name in ['tokenizer.json', 'tokenizer.model']:
    p = model_path / name
    if p.exists():
        shards[name] = hash_file(p)

print(f"\n✓ Hashed {len(shards)} files")

# Generate SVG
first_hash = list(shards.values())[0][:6] if shards else "4a9"
color = f"#{first_hash}"

svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 500 400">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:{color};stop-opacity:0.7"/>
      <stop offset="100%" style="stop-color:#0a0a1a;stop-opacity:1"/>
    </linearGradient>
    <filter id="glow">
      <feGaussianBlur stdDeviation="3" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
  </defs>

  <rect width="500" height="400" fill="url(#bg)" rx="20"/>

  <text x="250" y="50" text-anchor="middle" fill="#fff" font-size="28" font-weight="bold">MiniMax-M2.1</text>
  <text x="250" y="75" text-anchor="middle" fill="#888" font-size="12">MiniMaxAI/MiniMax-M2.1</text>
  <text x="250" y="110" text-anchor="middle" fill="{color}" font-size="16" font-weight="bold">456 BILLION PARAMETERS</text>

  <g transform="translate(250,220)" filter="url(#glow)">
    <circle r="70" fill="none" stroke="{color}" stroke-width="2" opacity="0.4"/>
    <circle r="55" fill="none" stroke="{color}" stroke-width="2" opacity="0.5"/>
    <circle r="40" fill="none" stroke="{color}" stroke-width="1.5" opacity="0.6"/>
    <circle r="25" fill="none" stroke="{color}" stroke-width="1" opacity="0.7"/>
    <circle r="10" fill="{color}" opacity="0.9"/>
    <g stroke="{color}" stroke-width="1" opacity="0.3">
      <line x1="-70" y1="0" x2="70" y2="0"/>
      <line x1="0" y1="-70" x2="0" y2="70"/>
      <line x1="-50" y1="-50" x2="50" y2="50"/>
      <line x1="-50" y1="50" x2="50" y2="-50"/>
    </g>
  </g>

  <text x="250" y="330" text-anchor="middle" fill="#666" font-size="11">{len(shards)} weight shards | content-addressed | living agent</text>

  <metadata>
    <agent xmlns="https://gentlyos.io/agent" version="1.0">
      <name>minimax_m2</name>
      <model>MiniMaxAI/MiniMax-M2.1</model>
      <params>456000000000</params>
      <born>{datetime.utcnow().isoformat()}Z</born>
      <generation>0</generation>
      <parent>genesis</parent>
      <weights>
{chr(10).join(f'        <shard name="{n}" hash="{h}" />' for n,h in shards.items())}
      </weights>
      <memory>
        <lora_chain></lora_chain>
        <observations>0</observations>
      </memory>
    </agent>
  </metadata>
</svg>'''

# Save
svg_path = Path("minimax_m2.svg")
svg_path.write_text(svg)

manifest = {
    "name": "minimax_m2",
    "model": "MiniMaxAI/MiniMax-M2.1",
    "params": 456_000_000_000,
    "shards": shards,
    "config": config,
    "agent_hash": hashlib.sha256(svg.encode()).hexdigest(),
}
Path("minimax_m2.json").write_text(json.dumps(manifest, indent=2))

print(f"\n" + "="*50)
print(f"✓ Agent SVG: minimax_m2.svg")
print(f"✓ Manifest:  minimax_m2.json")
print(f"✓ Hash:      {manifest['agent_hash'][:16]}...")
print(f"="*50)
print(f"\n456B params. One SVG. Your agent.")
print(f"Open minimax_m2.svg in browser to see it!")
