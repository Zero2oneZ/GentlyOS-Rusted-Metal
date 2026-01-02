#!/usr/bin/env python3
"""
HuggingFace Model → Living SVG Agent

Usage:
    python hf_to_agent.py MiniMaxAI/MiniMax-M2.1 --name minimax
    python hf_to_agent.py mistralai/Mistral-7B-v0.1 --name mistral
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
from datetime import datetime

def hash_file(path: Path) -> str:
    """SHA256 hash of file"""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def hash_bytes(data: bytes) -> str:
    """SHA256 hash of bytes"""
    return hashlib.sha256(data).hexdigest()

def generate_svg(name: str, model_id: str, shards: dict, config: dict) -> str:
    """Generate living SVG agent"""

    # Color from first shard hash
    first_hash = list(shards.values())[0] if shards else "000000"
    color = f"#{first_hash[:6]}"

    # Shard metadata
    shard_xml = "\n".join([
        f'      <shard name="{name}" hash="{h}" />'
        for name, h in shards.items()
    ])

    param_count = config.get('num_parameters', 'unknown')
    hidden_size = config.get('hidden_size', '?')
    num_layers = config.get('num_hidden_layers', '?')

    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 500 400">
  <!-- VISUAL: What I am -->
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

  <!-- Title -->
  <text x="250" y="50" text-anchor="middle" fill="#fff" font-size="28" font-weight="bold">{name}</text>
  <text x="250" y="75" text-anchor="middle" fill="#888" font-size="12">{model_id}</text>

  <!-- Stats -->
  <text x="250" y="110" text-anchor="middle" fill="{color}" font-size="14">
    {param_count} params | {hidden_size} hidden | {num_layers} layers
  </text>

  <!-- Neural visualization -->
  <g transform="translate(250,220)" filter="url(#glow)">
    <circle r="60" fill="none" stroke="{color}" stroke-width="2" opacity="0.5"/>
    <circle r="45" fill="none" stroke="{color}" stroke-width="1.5" opacity="0.6"/>
    <circle r="30" fill="none" stroke="{color}" stroke-width="1" opacity="0.7"/>
    <circle r="15" fill="{color}" opacity="0.8"/>

    <!-- Connections -->
    <g stroke="{color}" stroke-width="1" opacity="0.4">
      <line x1="-60" y1="0" x2="60" y2="0"/>
      <line x1="0" y1="-60" x2="0" y2="60"/>
      <line x1="-42" y1="-42" x2="42" y2="42"/>
      <line x1="-42" y1="42" x2="42" y2="-42"/>
    </g>
  </g>

  <!-- Shard count -->
  <text x="250" y="320" text-anchor="middle" fill="#666" font-size="11">
    {len(shards)} weight shards | content-addressed
  </text>

  <!-- BRAIN: What I do (WASM placeholder) -->
  <foreignObject x="0" y="340" width="500" height="50" style="display:none">
    <div xmlns="http://www.w3.org/1999/xhtml">
      <script type="application/wasm" data-loader="transformers"></script>
    </div>
  </foreignObject>

  <!-- MEMORY: What I learned -->
  <metadata>
    <agent xmlns="https://gentlyos.io/agent" version="1.0">
      <name>{name}</name>
      <model>{model_id}</model>
      <born>{datetime.utcnow().isoformat()}Z</born>
      <generation>0</generation>
      <parent>genesis</parent>

      <brain type="transformer">
        <config>{json.dumps(config)}</config>
      </brain>

      <weights>
{shard_xml}
      </weights>

      <memory>
        <lora_chain></lora_chain>
        <observations>0</observations>
        <evolutions>0</evolutions>
      </memory>
    </agent>
  </metadata>
</svg>'''

def scan_model_dir(model_path: Path) -> tuple[dict, dict]:
    """Scan model directory, hash all weight files"""
    shards = {}
    config = {}

    # Load config if exists
    config_path = model_path / "config.json"
    if config_path.exists():
        with open(config_path) as f:
            config = json.load(f)

    # Hash weight files
    for ext in ['*.safetensors', '*.bin', '*.pt', '*.gguf']:
        for path in model_path.glob(ext):
            print(f"Hashing {path.name}...")
            shards[path.name] = hash_file(path)

    # Hash tokenizer
    for name in ['tokenizer.json', 'tokenizer.model', 'vocab.json']:
        path = model_path / name
        if path.exists():
            shards[name] = hash_file(path)

    return shards, config

def main():
    parser = argparse.ArgumentParser(description='Convert HuggingFace model to Living SVG Agent')
    parser.add_argument('model', help='Model path or HuggingFace ID')
    parser.add_argument('--name', '-n', help='Agent name', default=None)
    parser.add_argument('--output', '-o', help='Output SVG path', default=None)
    parser.add_argument('--download', '-d', action='store_true', help='Download from HuggingFace first')

    args = parser.parse_args()

    model_path = Path(args.model)
    model_id = args.model
    name = args.name or model_path.name

    # Download if requested
    if args.download or not model_path.exists():
        print(f"Downloading {model_id}...")
        try:
            from huggingface_hub import snapshot_download
            model_path = Path(snapshot_download(model_id))
        except ImportError:
            print("pip install huggingface_hub")
            return

    if not model_path.exists():
        print(f"Model path not found: {model_path}")
        return

    print(f"Scanning {model_path}...")
    shards, config = scan_model_dir(model_path)

    if not shards:
        print("No weight files found!")
        return

    print(f"Found {len(shards)} files")

    # Generate SVG
    svg = generate_svg(name, model_id, shards, config)

    # Output
    output_path = Path(args.output) if args.output else Path(f"{name}.svg")
    output_path.write_text(svg)

    # Also save manifest
    manifest = {
        "name": name,
        "model_id": model_id,
        "shards": shards,
        "config": config,
        "agent_hash": hash_bytes(svg.encode()),
    }
    manifest_path = output_path.with_suffix('.json')
    manifest_path.write_text(json.dumps(manifest, indent=2))

    print(f"\n✓ Agent SVG: {output_path}")
    print(f"✓ Manifest:  {manifest_path}")
    print(f"✓ Hash:      {manifest['agent_hash'][:16]}...")
    print(f"\nOpen {output_path} in browser to see your agent!")

if __name__ == '__main__':
    main()
