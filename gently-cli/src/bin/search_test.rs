#![allow(dead_code, unused_imports, unused_variables)]
//! Search Integration Test
//! Tests ThoughtIndex search and RAG-lite functionality

use gently_brain::{LlamaInference, ConversationLearner, llama::{ChatMessage, ModelInfo}};
use gently_search::{ThoughtIndex, Thought, ContextRouter};

fn main() {
    println!("===========================================");
    println!("  GentlyOS Search Integration Test");
    println!("===========================================\n");

    // Initialize thought index
    let mut thought_index = match ThoughtIndex::load(ThoughtIndex::default_path()) {
        Ok(index) => {
            println!("[+] Loaded {} existing thoughts", index.thoughts().len());
            index
        }
        Err(_) => {
            println!("[*] Creating new thought index");
            ThoughtIndex::new()
        }
    };

    let search_router = ContextRouter::new().with_max_results(5);

    // Add some test thoughts
    println!("\n[*] Adding test thoughts...");
    let test_thoughts = vec![
        "Encryption is the process of converting readable data into code",
        "XOR is a binary operation used in cryptography",
        "Bitcoin uses SHA-256 for mining",
        "Hash functions produce fixed-length output from variable input",
        "Public key cryptography uses two keys: public and private",
        "AES is a symmetric encryption algorithm",
        "RSA is an asymmetric encryption algorithm",
        "The blockchain is a distributed ledger technology",
    ];

    for content in test_thoughts {
        let thought = Thought::with_source(content, "test");
        thought_index.add_thought(thought);
    }

    let stats = thought_index.stats();
    println!("[+] Index: {} thoughts, {} wormholes, {} domains\n",
        stats.thought_count, stats.wormhole_count, stats.domains_used);

    // Test searches
    println!("===========================================");
    println!("  Testing Search");
    println!("===========================================\n");

    let queries = vec![
        "encryption",
        "XOR crypto",
        "bitcoin hash",
        "public key",
    ];

    for query in queries {
        println!("Query: \"{}\"", query);
        println!("-----------------------------------------");

        let results = search_router.search(query, &thought_index, None);

        if results.is_empty() {
            println!("  No results\n");
        } else {
            for (i, result) in results.iter().take(3).enumerate() {
                let preview: String = result.thought.content.chars().take(60).collect();
                println!("  {}. [{:.2}] {}...", i + 1, result.score, preview);
            }
            println!("  ({} total results)\n", results.len());
        }
    }

    // Test RAG-lite context building
    println!("===========================================");
    println!("  Testing RAG-lite Context");
    println!("===========================================\n");

    let user_query = "How does encryption work?";
    println!("User query: \"{}\"\n", user_query);

    let results = search_router.search(user_query, &thought_index, None);
    let context = if !results.is_empty() {
        let context_parts: Vec<String> = results
            .iter()
            .take(3)
            .map(|r| format!("- {}", r.thought.content))
            .collect();
        format!("Relevant context from memory:\n{}", context_parts.join("\n"))
    } else {
        String::new()
    };

    println!("Context for LLM:\n{}\n", context);

    // Load model and test with context
    let model_info = ModelInfo::tiny_llama();
    let model_path = model_info.model_path();

    if model_path.exists() {
        let mut llama = LlamaInference::new();
        if llama.load(&model_path).is_ok() {
            println!("[+] Model loaded, testing RAG response...\n");

            let system_prompt = format!(
                "You are Gently, a helpful assistant. Be concise.\n\n{}",
                context
            );

            let messages = vec![
                ChatMessage::system(&system_prompt),
                ChatMessage::user(user_query),
            ];

            match llama.chat(&messages) {
                Ok(response) => {
                    println!("Response (with context):\n{}\n", response);
                }
                Err(e) => {
                    println!("[!] Inference failed: {}\n", e);
                }
            }
        }
    } else {
        println!("[!] Model not found, skipping LLM test\n");
    }

    // Save thought index
    match thought_index.save(ThoughtIndex::default_path()) {
        Ok(_) => println!("[+] Thoughts saved to {}", ThoughtIndex::default_path().display()),
        Err(e) => println!("[!] Save failed: {}", e),
    }

    println!("\n===========================================");
    println!("  Test Complete!");
    println!("===========================================");
}
