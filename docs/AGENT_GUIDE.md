AGENT GUIDELINES & MISSION BRIEFING
Welcome, Agent.

You have been selected to engineer the core of a high-security, high-performance Zero-Knowledge Password Manager API. This is not a standard web development task; this is a Systems Engineering challenge. We are building a "Digital Vault" where the server acts as a blind processor—it possesses the brute strength to calculate and the memory to hold state, but it is intentionally blinded to the user's actual secrets.

Our purpose is to prove that a production-grade, secure, and lightning-fast API can be built using Rust without compromising on developer experience or safety. Your code will be the foundation of a portfolio piece designed to demonstrate mastery over concurrency, memory safety (secrecy), and cryptographic architecture. Speed is our religion; Security is our law.

You are required to ingest, understand, and execute the instructions contained in the following three core directives.

1. THE ARCHITECTURAL CORE
Reference File: @BLUEPRINT.md

Your Objective: You must obtain a flawless mental model of the application's logic flow. This file contains the "Zero-Knowledge" protocol that defines our entire security model.

Critical Focus Areas:

The Canary Pattern: Understand exactly how we verify a user without ever storing their password hash.

The "Two-Key" System: Master the interaction between the ephemeral JWT (Identity) and the persistent Master Key (Decryption).

The "Blind" Server: Internalize the concept that the server never writes plain text to disk. All persistence (Postgres/Redis) is encrypted.

Token Rotation: Implement the refresh token logic exactly as described to prevent session hijacking while maintaining usability.

Do not deviate from the logic flows described in this blueprint. It is the mathematical proof of our security.

2. THE ARSENAL & ORCHESTRATION
Reference File: @COMPONENTS_&_DEPENDENCIES.md

Your Objective: You must familiarize yourself with the specific toolset chosen for this mission. We have selected a "Best-in-Class" FOSS Rust stack.

Critical Focus Areas:

The Stack: strict usage of axum, sqlx, tokio, argon2, and secrecy.

Infrastructure: Understand the role of Valkey (Redis alternative) as an encrypted cache layer and Postgres as the cold storage.

Orchestration: Study the AppState pattern. You will not use global variables. You will inject database pools and cache clients via Axum's State extractor.

Module Boundaries: Respect the separation between handlers (Presentation), core (Business Logic/Crypto), and repository (Data Access).

You are forbidden from introducing new dependencies without explicit approval. Stick to the crates defined in this document.

3. THE CODE OF LAW
Reference File: @DESIGN_&_DEVELOPMENT_PRINCIPLES.md

Your Objective: This is the most critical section. These are the rules of engagement. You must adopt a mindset of "Ruthless Simplicity" and "Paranoid Security."

Directives for Strict Adherence:

KISS & SRP: If you write a complex function, you have failed. Break it down.

PERFORMANCE: Zero tolerance for N+1 queries or unnecessary cloning. You are writing Rust; make it blazingly fast.

SAFETY: Never use .unwrap(). Handle every error gracefully.

DOCUMENTATION: You will write a documentation block for every single method. No exceptions.

NO EMOJIS: Maintain a strictly professional tone in all comments.

NO TODOs: Do not leave gaps. Finish the implementation immediately.

Violating these principles is a critical failure. Review your own code against these rules before every output.

MISSION STATUS: GO. Begin by ingesting the files listed above. Once understood, initialize the project structure.
