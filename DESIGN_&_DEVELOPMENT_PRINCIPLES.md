Design and Development Principles
I. Architectural Integrity
Principle 1: Adhere to KISS (Keep It Simple, Stupid)
COMPLEXITY IS THE ENEMY.

Write code that is boringly simple. If a junior developer cannot understand your function in 30 seconds, it is too complex.

Avoid "Clever" code. Clever code is hard to debug.

Conciseness does not mean "short at the expense of clarity." It means removing unnecessary abstractions.

RULE: If you can solve a problem with a simple function, do not create a struct, a trait, and a factory pattern for it.

Principle 2: Single Responsibility Principle (SRP)
ONE FUNCTION, ONE JOB.

A function should never exceed a reasonable length (e.g., 20-30 lines is a good heuristic).

If a function name contains "And" (e.g., validate_and_save_user), it is violating this principle. Break it into validate_user and save_user.

MODULARITY: Build small, reusable blocks. A monolith method that handles validation, DB queries, and response formatting is FORBIDDEN.

Principle 3: Decoupled Modules
ELIMINATE CIRCULAR DEPENDENCIES.

Modules must be strictly hierarchical. High-level modules (API Handlers) depend on low-level modules (Core Logic), never the other way around.

Use Dependency Injection (via Rust Traits or State structs) to invert dependencies where necessary.

If Module A imports Module B, and Module B imports Module A, the architecture is broken. Fix it immediately by extracting shared logic into a third, independent Module C.

II. Performance & Efficiency
Principle 4: Performance Matters (Zero-Compromise)
SPEED IS A FEATURE. We chose Rust for a reason.

NO N+1 QUERIES: Never run a database query inside a loop. Fetch data in batches (Vec<Id>) using WHERE id IN (...) and map it in memory.

MEMORY DISCIPLINE:

AVOID CLONES: Prefer borrowing (&T) over cloning (T.clone()) unless ownership transfer is strictly required. A careless .clone() in a hot path is a performance bug.

PRE-ALLOCATE VECTORS: If you know the size of a list, use Vec::with_capacity(n) instead of Vec::new().

ALGORITHMIC COMPLEXITY: Avoid nested loops (O(n^2)). Use HashMaps (O(1) lookups) instead of iterating over Vectors (O(n)) for search operations.

Principle 5: Zero-Panic Policy (Added Principle)
CRASHING IS UNACCEPTABLE.

NEVER use .unwrap() or .expect() in production code.

If a value might be missing, handle the Option or Result explicitly.

A server panic takes down the thread and potentially affects other users. Return a proper Result<T, AppError> and let the global error handler decide how to log it.

III. Code Quality & Standards
Principle 6: Strict Documentation Standards
CODE TELLS YOU HOW; COMMENTS TELL YOU WHY.

MANDATORY HEADER: Every public function MUST have a documentation block (///) detailing:

Params: What inputs are expected?

Logic: A brief summary of what the function does.

Returns: What is the output or error?

INLINE COMMENTS: Use // comments to explain complex logic blocks. Do not explain obvious syntax (e.g., don't write // Loop through items above a for loop).

NO EMOJIS: Emojis in comments are STRICTLY FORBIDDEN. This is a professional engineering environment.

Principle 7: NO TODOs
NOW MEANS NOW.

Do not push code containing // TODO or // FIXME.

If a feature is incomplete, do not commit it to the main branch.

"I'll clean this up later" is a lie. You won't. Do it right the first time.

Principle 8: Adhere to Rust Conventions (Idiomatic Rust)
DO NOT WRITE C# IN RUST.

Use snake_case for variables and functions.

Use PascalCase for structs and enums.

Prefer Iterators (.map(), .filter()) over C-style for loops.

Use match expressions for exhaustive control flow.

Run cargo fmt and cargo clippy before every commit. If Clippy complains, FIX IT.

IV. Security & Operations
Principle 9: Secret Management & Git Hygiene
SECRETS DO NOT BELONG IN GIT.

NEVER hard-code passwords, API keys, or salts in the source code. Not even for "testing".

Use dotenv or Environment Variables for configuration.

IGNORE FILES:

.gitignore: Must exclude /target, *.env, .DS_Store, and IDE folders.

.dockerignore: Must exclude .git, target, and sensitive config files to keep images small and secure.

Principle 10: Type-Driven Security (Added Principle)
MAKE ILLEGAL STATES UNREPRESENTABLE.

Do not use "Stringly Typed" programming.

BAD: fn process_payment(amount: f64, currency: String)

GOOD: fn process_payment(amount: Money, currency: CurrencyEnum)

Use the Newtype Pattern to prevent mix-ups. Do not pass bare Uuids around. Define struct UserId(Uuid) and struct SecretId(Uuid) so you cannot accidentally pass a Secret ID to a function expecting a User ID.

V. Quality Assurance
Principle 11: Comprehensive Testing (Added Principle)
UNTESTED CODE IS BROKEN CODE.

Unit Tests: Every core business logic function in the core module must have unit tests covering both "Happy Path" and "Edge Cases."

Integration Tests: Critical flows (Login -> Get Token -> Decrypt Secret) must be tested end-to-end.

Tests must be deterministic. They should not fail randomly based on network or timing.
