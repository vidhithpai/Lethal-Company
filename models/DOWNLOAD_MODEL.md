# Download a local model for enhanced offline analysis

## Recommended: Phi-3 Mini (3.8B, ~2.3GB, very fast on CPU)
```bash
wget https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf/resolve/main/Phi-3-mini-4k-instruct-q4.gguf -O models/phi3-mini-q4.gguf
pip install llama-cpp-python
```

## Alternative: TinyLlama (1.1B, ~600MB, fastest on old hardware)
```bash
wget https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf -O models/tinyllama-q4.gguf
pip install llama-cpp-python
```

## No download needed (automatic):
```bash
pip install transformers torch --index-url https://download.pytorch.org/whl/cpu
# CodeBERT vulnerability classifier downloads automatically on first use (~500MB)
```

## Zero install (always works):
The rule-based explainer requires no model download and works offline immediately.
