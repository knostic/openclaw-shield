/**
 * Detection patterns for secrets, PII, destructive commands, and sensitive files.
 */

export type NamedPattern = { name: string; pattern: RegExp };

// ============================================================================
// Secret Patterns
// ============================================================================

export const SECRET_PATTERNS: NamedPattern[] = [
  // --- AWS ---
  { name: "aws_access_key", pattern: /AKIA[0-9A-Z]{16}/ },
  { name: "aws_secret_key", pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?/ },

  // --- Payment ---
  { name: "stripe_key", pattern: /[sr]k[-_](?:live|test)[-_][a-zA-Z0-9]{20,}/ },

  // --- GitHub ---
  { name: "github_token", pattern: /gh[pousr]_[a-zA-Z0-9]{36}/ },
  { name: "github_fine_grained_pat", pattern: /github_pat_[a-zA-Z0-9_]{22,}/ },

  // --- AI / Model Platforms ---
  { name: "openai_key", pattern: /sk-[a-zA-Z0-9]{20,}/ },
  { name: "anthropic_key", pattern: /sk-ant-[a-zA-Z0-9_-]{20,}/ },
  { name: "google_api_key", pattern: /AIza[0-9A-Za-z_-]{35}/ },
  { name: "gcp_service_account", pattern: /"type"\s*:\s*"service_account"/ },
  { name: "azure_openai_key", pattern: /(?:azure|openai)[_-]?(?:api)?[_-]?key\s*[:=]\s*["']?[a-fA-F0-9]{32}["']?/i },
  { name: "huggingface_token", pattern: /hf_[a-zA-Z0-9]{34,}/ },
  { name: "replicate_token", pattern: /r8_[a-zA-Z0-9]{36,}/ },
  { name: "cohere_api_key", pattern: /(?:cohere|co[-_]?api)[-_]?key\s*[:=]\s*["']?[a-zA-Z0-9_-]{40,}["']?/i },
  { name: "together_ai_key", pattern: /(?:together|together[-_]?ai)[-_]?(?:api)?[-_]?key\s*[:=]\s*["']?[a-zA-Z0-9_-]{40,}["']?/i },
  { name: "mistral_api_key", pattern: /(?:mistral[-_]?(?:api)?[-_]?key\s*[:=]\s*["']?[a-zA-Z0-9_-]{32,}["']?)/i },
  { name: "groq_api_key", pattern: /gsk_[a-zA-Z0-9]{48,}/ },
  { name: "deepseek_api_key", pattern: /(?:deepseek)[-_]?(?:api)?[-_]?key\s*[:=]\s*["']?sk-[a-zA-Z0-9]{48,}["']?/i },

  // --- Messaging / Communication ---
  { name: "slack_token", pattern: /xox[bpras]-[a-zA-Z0-9-]{10,}/ },
  { name: "slack_webhook", pattern: /hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/ },
  { name: "sendgrid_key", pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/ },
  { name: "twilio_api_key", pattern: /SK[0-9a-fA-F]{32}/ },
  { name: "mailgun_api_key", pattern: /key-[a-zA-Z0-9]{32}/ },

  // --- Package Registries ---
  { name: "npm_token", pattern: /npm_[a-zA-Z0-9]{36,}/ },

  // --- Crypto / Private Keys ---
  { name: "private_key", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/ },
  { name: "eth_private_key", pattern: /(?:0x)?[0-9a-fA-F]{64}(?=\s|$|["'])/ },
  { name: "mnemonic_seed", pattern: /(?:mnemonic|seed\s*phrase|recovery\s*phrase|backup\s*phrase)\s*[:=]?\s*["']?(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}["']?/i },

  // --- Cryptocurrency Exchanges ---
  { name: "coinbase_api_key", pattern: /(?:coinbase)[-_]?(?:api)?[-_]?(?:key|secret)\s*[:=]\s*["']?[a-zA-Z0-9_-]{20,}["']?/i },
  { name: "binance_api_key", pattern: /(?:binance)[-_]?(?:api)?[-_]?(?:key|secret)\s*[:=]\s*["']?[a-zA-Z0-9]{64}["']?/i },

  // --- Stock Trading ---
  { name: "alpaca_api_key", pattern: /(?:AK|PK)[a-zA-Z0-9]{20}/ },
  { name: "trading_api_key", pattern: /(?:trading|brokerage|alpaca|tradier|interactive[-_]?brokers)[-_]?(?:api)?[-_]?(?:key|secret|token)\s*[:=]\s*["']?[a-zA-Z0-9_-]{20,}["']?/i },

  // --- Auth Tokens ---
  { name: "jwt", pattern: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/ },
  { name: "bearer_token", pattern: /(?:Authorization|authorization)\s*[:=]\s*["']?Bearer\s+[a-zA-Z0-9_.\-/+=]{20,}/ },
  { name: "generic_api_key", pattern: /(?:api[-_]?key|api[-_]?secret|secret[-_]?key)\s*[:=]\s*["']?[a-zA-Z0-9_.\-/+=]{20,}["']?/i },
  { name: "vault_token", pattern: /hvs\.[a-zA-Z0-9_-]{24,}/ },

  // --- Database / Infrastructure URLs ---
  { name: "database_url", pattern: /(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^\s]{10,}/ },
  { name: "redis_url", pattern: /rediss?:\/\/[^\s]{10,}/ },

  // --- Cloud / Platform Tokens ---
  { name: "supabase_key", pattern: /(?:supabase|SUPABASE)[-_]?(?:anon|service[-_]?role)?[-_]?key\s*[:=]\s*["']?eyJ[a-zA-Z0-9_-]{20,}["']?/ },
  { name: "vercel_token", pattern: /vercel_[a-zA-Z0-9_-]{24,}/ },
  { name: "heroku_api_key", pattern: /(?:heroku[-_]?(?:api)?[-_]?key\s*[:=]\s*["']?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}["']?)/i },
  { name: "digitalocean_token", pattern: /dop_v1_[a-fA-F0-9]{64}/ },
  { name: "cloudflare_api_token", pattern: /cf_[a-zA-Z0-9_-]{40,}/ },
  { name: "firebase_key", pattern: /(?:firebase|FIREBASE)[-_]?(?:api)?[-_]?(?:key|secret|token)\s*[:=]\s*["']?[a-zA-Z0-9_-]{20,}["']?/ },

  // --- Monitoring / Observability ---
  { name: "datadog_api_key", pattern: /(?:datadog|DD)[-_]?(?:api)?[-_]?key\s*[:=]\s*["']?[a-fA-F0-9]{32}["']?/i },
  { name: "sentry_dsn", pattern: /https:\/\/[a-f0-9]{32}@[a-z0-9.]+sentry[a-z.]*\/[0-9]+/ },
];

// ============================================================================
// PII Patterns
// ============================================================================

export const PII_PATTERNS: NamedPattern[] = [
  { name: "email", pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/ },
  { name: "us_ssn", pattern: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/ },
  { name: "credit_card", pattern: /\b[3-6]\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b/ },
  { name: "us_phone", pattern: /\b(?:\+?1[-.\s]?)?(?:\(?[2-9]\d{2}\)?[-.\s]?)[2-9]\d{2}[-.\s]?\d{4}\b/ },
  { name: "intl_phone", pattern: /\b\+[2-9]\d{0,2}[-.\s]?\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b/ },
  { name: "iban", pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,23}\b/ },
  { name: "cn_id_number", pattern: /\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b/ },
  { name: "cn_phone", pattern: /\b1[3-9]\d{9}\b/ },
  { name: "passport_number", pattern: /\b(?:passport|护照)[-_\s]*(?:no|number|号)?[-_\s:]*[A-Z0-9]{5,12}\b/i },
];

// ============================================================================
// Destructive Command Pattern
// ============================================================================

export const DEFAULT_DESTRUCTIVE_CMD =
  /\b(rm|rmdir|unlink|del|format|mkfs|dd\s+if=|DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE|DELETE\s+FROM|kubectl\s+delete|docker\s+rm|docker\s+rmi|git\s+push\s+.*--force|git\s+reset\s+--hard|chmod\s+777|iptables\s+-F|systemctl\s+stop)\b/i;

// ============================================================================
// Sensitive File Patterns
// ============================================================================

export const DEFAULT_SENSITIVE_FILE_PATTERNS: RegExp[] = [
  /\.env(?:\.|$)/i,
  /credentials\.json$/i,
  /\.pem$/i,
  /\.key$/i,
  /\.p12$/i,
  /\.pfx$/i,
  /id_(?:rsa|ed25519|ecdsa|dsa)(?:\.pub)?$/i,
  /known_hosts$/i,
  /\.ssh\/config$/i,
  /\.netrc$/i,
  /\.npmrc$/i,
  /\.pypirc$/i,
  /token(?:s)?\.json$/i,
  /secret(?:s)?\.(?:ya?ml|json|toml)$/i,
  /\.aws\/(?:credentials|config)$/i,
  /\.kube\/config$/i,
  /\/etc\/shadow$/,
  /\/etc\/passwd$/,
  /terraform\.tfstate/i,
  /wallet\.dat$/i,
  /keystore\//i,
  /\.gcloud\//i,
  /\.docker\/config\.json$/i,
  /\.gradle\/gradle\.properties$/i,
  /\.cargo\/credentials/i,
  /trading.*config/i,
  /\.anthropic/i,
  /\.openai/i,
];
