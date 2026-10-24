# Vendored skill

OpenPlow reuses Cloudflare's MIT-licensed `security-audit` skill for its
attack-class prompts, finding schema, and audit methodology. The skill is **not**
committed here yet; vendor it into `skills/security-audit/` so hunters can load
the matching class file for each attack class.

```bash
# from the repo root
git clone --depth 1 https://github.com/cloudflare/security-audit-skill /tmp/sa
cp -r /tmp/sa/skills/security-audit skills/security-audit
cp /tmp/sa/LICENSE skills/security-audit/LICENSE
```

The attack-class names in `openplow/stages/recon.py` (`ATTACK_CLASSES`) line up
one-to-one with the skill's class files:

| OpenPlow class | Skill file |
| --- | --- |
| web-protocol-and-auth | `WEB-PROTOCOL-AND-AUTH.md` |
| memory-safety-and-binary | `MEMORY-SAFETY-AND-BINARY.md` |
| ai-and-llm | `AI-AND-LLM.md` |
| client-side | `CLIENT-SIDE.md` |
| supply-chain-and-release | `SUPPLY-CHAIN-AND-RELEASE.md` |
| cloud-and-deployment | `CLOUD-AND-DEPLOYMENT.md` |
| protocols-rpc-and-messaging | `PROTOCOLS-RPC-AND-MESSAGING.md` |
| resource-exhaustion-and-availability | `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md` |
| data-isolation-and-lifecycle | `DATA-ISOLATION-AND-LIFECYCLE.md` |
| desktop-mobile-and-local-ipc | `DESKTOP-MOBILE-AND-LOCAL-IPC.md` |

Retain the skill's MIT `LICENSE` alongside the vendored files; it is also
acknowledged in the repo-root `NOTICE`.
