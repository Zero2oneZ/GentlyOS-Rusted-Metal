#![allow(dead_code, unused_imports, unused_variables)]
//! Simple LLM test without TUI
//! Tests model loading and inference

use gently_brain::{LlamaInference, llama::{ChatMessage, ModelInfo, download_model}};

fn main() {
    println!("===========================================");
    println!("  GentlyOS Chat - LLM Test");
    println!("===========================================\n");

    // Check model path
    let model_info = ModelInfo::tiny_llama();
    let model_path = model_info.model_path();

    println!("Model: {}", model_info.name);
    println!("Size:  {} MB", model_info.size_mb);
    println!("Path:  {}\n", model_path.display());

    // Check if model exists
    if !model_path.exists() {
        println!("[!] Model not found. Downloading...");
        println!("    This will download ~669MB from HuggingFace.\n");

        match download_model(&model_info) {
            Ok(path) => {
                println!("[+] Downloaded to: {}\n", path.display());
            }
            Err(e) => {
                println!("[!] Download failed: {}", e);
                println!("    Running in simulation mode.\n");
                test_simulation();
                return;
            }
        }
    } else {
        println!("[+] Model found at: {}\n", model_path.display());
    }

    // Load model
    println!("[*] Loading model into memory...");
    let mut llama = LlamaInference::new();

    match llama.load(&model_path) {
        Ok(_) => {
            println!("[+] Model loaded successfully!\n");
        }
        Err(e) => {
            println!("[!] Load failed: {}", e);
            println!("    Running in simulation mode.\n");
            test_simulation();
            return;
        }
    }

    // Test inference
    println!("===========================================");
    println!("  Testing Inference");
    println!("===========================================\n");

    let test_prompts = vec![
        "What is 2 + 2?",
        "Explain XOR in one sentence.",
        "Hello!",
    ];

    for (i, prompt) in test_prompts.iter().enumerate() {
        println!("Test {}: \"{}\"", i + 1, prompt);
        println!("-----------------------------------------");

        let messages = vec![
            ChatMessage::system("You are Gently, a helpful assistant. Be very brief."),
            ChatMessage::user(prompt),
        ];

        match llama.chat(&messages) {
            Ok(response) => {
                println!("Response: {}\n", response.trim());
            }
            Err(e) => {
                println!("Error: {}\n", e);
            }
        }
    }

    println!("===========================================");
    println!("  Test Complete!");
    println!("===========================================");
    println!("\nTo use the interactive chat TUI, run:");
    println!("  ./target/release/gently-chat");
}

fn test_simulation() {
    println!("===========================================");
    println!("  Simulation Mode Test");
    println!("===========================================\n");

    let llama = LlamaInference::new();
    println!("Model loaded: {}", llama.is_loaded());
    println!("\nTo download the model manually:");
    println!("  mkdir -p ~/.gentlyos/models");
    println!("  cd ~/.gentlyos/models");
    println!("  wget https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf");
}
