#!/usr/bin/env node

/**
 * Eresus AppSec Skills — Universal Installer
 *
 * Usage:
 *   npx @eresus/appsec-skills                       # interactive
 *   npx @eresus/appsec-skills --agent claude         # Claude Code
 *   npx @eresus/appsec-skills --agent codex          # OpenAI Codex
 *   npx @eresus/appsec-skills --agent antigravity    # Google Antigravity
 *   npx @eresus/appsec-skills --agent cursor         # Cursor
 *   npx @eresus/appsec-skills --dir /custom/path     # custom directory
 *   npx @eresus/appsec-skills --list                 # list available skills
 *   npx @eresus/appsec-skills --skills sast,audit    # install specific skills only
 */

import { existsSync, mkdirSync, cpSync, readdirSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const SKILLS_SRC = resolve(__dirname, "..", "skills");

const SKILL_MAP = {
  sast: "eresus-sast-scanner",
  audit: "eresus-manual-security-audit",
  remediate: "eresus-remediator",
  pr: "eresus-pr-security-review",
  threat: "eresus-threat-modeler",
  serial: "eresus-serialization-review",
  variant: "eresus-variant-analysis",
  codeql: "eresus-codeql-heuristics",
  deser: "eresus-deser-audit",
  python: "eresus-python-audit",
  php: "eresus-php-audit",
};

const AGENT_DIRS = {
  claude: join(homedir(), ".claude", "skills"),
  codex: join(homedir(), ".codex", "skills"),
  antigravity: join(homedir(), ".gemini", "antigravity", "skills"),
  cursor: join(homedir(), ".cursor", "skills"),
};

function parseArgs(argv) {
  const args = { agent: null, dir: null, list: false, skills: null, help: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") args.help = true;
    else if (a === "--list" || a === "-l") args.list = true;
    else if ((a === "--agent" || a === "-a") && argv[i + 1]) args.agent = argv[++i].toLowerCase();
    else if ((a === "--dir" || a === "-d") && argv[i + 1]) args.dir = argv[++i];
    else if ((a === "--skills" || a === "-s") && argv[i + 1]) args.skills = argv[++i].split(",").map(s => s.trim());
  }
  return args;
}

function printBanner() {
  console.log("");
  console.log("  ╔══════════════════════════════════════════════════════╗");
  console.log("  ║          🕷️  Eresus AppSec Skills Installer          ║");
  console.log("  ╚══════════════════════════════════════════════════════╝");
  console.log("");
}

function printHelp() {
  console.log("Usage: npx @eresus/appsec-skills [options]");
  console.log("");
  console.log("Options:");
  console.log("  --agent, -a <name>    Target agent: claude, codex, antigravity, cursor");
  console.log("  --dir, -d <path>      Install to a custom directory");
  console.log("  --skills, -s <list>   Comma-separated skill shortcodes (see --list)");
  console.log("  --list, -l            List available skills");
  console.log("  --help, -h            Show this help");
  console.log("");
  console.log("Examples:");
  console.log("  npx @eresus/appsec-skills --agent claude");
  console.log("  npx @eresus/appsec-skills --agent antigravity --skills sast,audit");
  console.log("  npx @eresus/appsec-skills --dir ./my-skills");
}

function listSkills() {
  console.log("Available skills:");
  console.log("");
  for (const [short, full] of Object.entries(SKILL_MAP)) {
    console.log(`  ${short.padEnd(12)} → ${full}`);
  }
  console.log("");
  console.log("Use --skills sast,audit,... to install specific skills.");
}

function askQuestion(query) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((res) => rl.question(query, (answer) => { rl.close(); res(answer.trim()); }));
}

async function resolveTargetDir(args) {
  if (args.dir) return resolve(args.dir);
  if (args.agent && AGENT_DIRS[args.agent]) return AGENT_DIRS[args.agent];

  console.log("Select your AI agent:");
  console.log("  1) Claude Code       (~/.claude/skills/)");
  console.log("  2) OpenAI Codex      (~/.codex/skills/)");
  console.log("  3) Antigravity       (~/.gemini/antigravity/skills/)");
  console.log("  4) Cursor            (~/.cursor/skills/)");
  console.log("  5) Custom path");
  console.log("");

  const choice = await askQuestion("Enter choice [1-5]: ");
  const map = { "1": "claude", "2": "codex", "3": "antigravity", "4": "cursor" };

  if (map[choice]) return AGENT_DIRS[map[choice]];
  if (choice === "5") {
    const custom = await askQuestion("Enter custom skills directory path: ");
    return resolve(custom);
  }

  console.log("Invalid choice, defaulting to Claude Code.");
  return AGENT_DIRS.claude;
}

function resolveSkills(args) {
  if (args.skills) {
    return args.skills.map((s) => SKILL_MAP[s] || s).filter(Boolean);
  }
  return Object.values(SKILL_MAP);
}

function install(targetDir, skillNames) {
  if (!existsSync(targetDir)) {
    mkdirSync(targetDir, { recursive: true });
    console.log(`  📁 Created ${targetDir}`);
  }

  let installed = 0;
  let skipped = 0;

  for (const skill of skillNames) {
    const src = join(SKILLS_SRC, skill);
    const dest = join(targetDir, skill);

    if (!existsSync(src)) {
      console.log(`  ⚠️  Skill not found: ${skill}`);
      skipped++;
      continue;
    }

    cpSync(src, dest, { recursive: true, force: true });
    console.log(`  ✅ ${skill}`);
    installed++;
  }

  return { installed, skipped };
}

async function main() {
  const args = parseArgs(process.argv);
  printBanner();

  if (args.help) { printHelp(); process.exit(0); }
  if (args.list) { listSkills(); process.exit(0); }

  const targetDir = await resolveTargetDir(args);
  const skillNames = resolveSkills(args);

  console.log(`Installing ${skillNames.length} skills to: ${targetDir}`);
  console.log("");

  const { installed, skipped } = install(targetDir, skillNames);

  console.log("");
  console.log(`  🎯 Done: ${installed} installed, ${skipped} skipped`);
  console.log("");
  console.log("  Skills are ready. Start your agent and use a trigger phrase like:");
  console.log('  → "do a deep security audit"');
  console.log('  → "find exploit chains"');
  console.log('  → "review this like a pentester"');
  console.log('  → "threat model this feature"');
  console.log('  → "scan this repo for vulnerabilities"');
  console.log("");
}

main().catch((err) => { console.error("Fatal:", err.message); process.exit(1); });
