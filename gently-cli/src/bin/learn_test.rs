#![allow(dead_code, unused_imports, unused_variables)]
//! Knowledge Learning Test
//! Tests ConversationLearner functionality

use gently_brain::{ConversationLearner, LlamaInference, llama::{ChatMessage, ModelInfo}};

fn main() {
    println!("===========================================");
    println!("  GentlyOS Knowledge Learning Test");
    println!("===========================================\n");

    // Initialize learner
    let mut learner = ConversationLearner::new();

    // Try to load existing knowledge
    match learner.load() {
        Ok(_) => println!("[+] Loaded existing knowledge"),
        Err(e) => println!("[!] No existing knowledge: {}", e),
    }

    println!("Initial state: {}\n", learner.learning_summary());

    // Load the LLM
    let model_info = ModelInfo::tiny_llama();
    let model_path = model_info.model_path();

    let mut llama = LlamaInference::new();
    if model_path.exists() {
        if let Err(e) = llama.load(&model_path) {
            println!("[!] Model load failed: {}", e);
            test_learning_only(&mut learner);
            return;
        }
        println!("[+] Model loaded\n");
    } else {
        println!("[!] Model not found, running learning-only test\n");
        test_learning_only(&mut learner);
        return;
    }

    // Test conversations that generate knowledge
    let test_exchanges = vec![
        ("What is encryption?", "Encryption is the process of converting readable data into an unreadable format to protect it from unauthorized access. It requires a key to decrypt the data back to its original form."),
        ("How does XOR work?", "XOR is a binary operation that returns 1 when inputs differ and 0 when they're the same. It is used in encryption because XOR is reversible."),
        ("What is Bitcoin?", "Bitcoin is a decentralized digital currency that uses cryptography for security. It is part of a blockchain network where transactions are verified by miners."),
    ];

    println!("===========================================");
    println!("  Testing Knowledge Extraction");
    println!("===========================================\n");

    for (user_msg, assistant_msg) in test_exchanges {
        println!("User: {}", user_msg);
        println!("Assistant: {}\n", &assistant_msg[..assistant_msg.len().min(100)]);

        let result = learner.learn_from_exchange(user_msg, assistant_msg);

        if !result.concepts_added.is_empty() {
            println!("[{}]", result.summary);
            println!("  Concepts: {:?}", result.concepts_added);
            println!("  Edges: {}\n", result.edges_added);
        } else {
            println!("[No new concepts learned]\n");
        }
    }

    // Now test with actual LLM responses
    println!("===========================================");
    println!("  Testing with Live LLM");
    println!("===========================================\n");

    let live_questions = vec![
        "What is a hash function?",
        "Explain public key cryptography.",
    ];

    for question in live_questions {
        println!("User: {}", question);

        let messages = vec![
            ChatMessage::system("You are Gently, a helpful assistant. Give clear, educational answers."),
            ChatMessage::user(question),
        ];

        match llama.chat(&messages) {
            Ok(response) => {
                println!("Assistant: {}...\n", &response[..response.len().min(150)]);

                let result = learner.learn_from_exchange(question, &response);
                if !result.concepts_added.is_empty() {
                    println!("[{}]\n", result.summary);
                }
            }
            Err(e) => {
                println!("[Error: {}]\n", e);
            }
        }
    }

    // Show the knowledge graph
    println!("===========================================");
    println!("  Knowledge Graph");
    println!("===========================================\n");

    println!("{}", learner.render_ascii(20));

    println!("\n===========================================");
    println!("  Session Summary");
    println!("===========================================\n");

    println!("{}", learner.learning_summary());
    println!("\nConcepts learned this session:");
    for concept in learner.session_concepts().iter().take(15) {
        println!("  - {} ({:?})", concept.concept, concept.node_type);
    }

    // Save knowledge
    match learner.save() {
        Ok(_) => println!("\n[+] Knowledge saved to {}", ConversationLearner::default_path().display()),
        Err(e) => println!("\n[!] Save failed: {}", e),
    }

    println!("\n===========================================");
    println!("  Test Complete!");
    println!("===========================================");
}

fn test_learning_only(learner: &mut ConversationLearner) {
    println!("===========================================");
    println!("  Learning-Only Test (No LLM)");
    println!("===========================================\n");

    // Test with canned responses
    let exchanges = vec![
        ("What is encryption?", "Encryption is the process of converting readable data into code. AES is a type of symmetric encryption. RSA is used for public key cryptography."),
        ("How do hash functions work?", "A hash function takes input and produces a fixed-size output. SHA-256 is a cryptographic hash function. Hash functions are used in blockchain."),
    ];

    for (user, assistant) in exchanges {
        println!("User: {}", user);
        println!("Assistant: {}\n", assistant);

        let result = learner.learn_from_exchange(user, assistant);
        println!("[{}]\n", result.summary);
    }

    println!("{}", learner.render_ascii(20));

    match learner.save() {
        Ok(_) => println!("\n[+] Knowledge saved"),
        Err(e) => println!("\n[!] Save failed: {}", e),
    }
}
