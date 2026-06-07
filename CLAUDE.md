# FloppyGuard

## Skill routing

When the user's request matches an available skill, invoke it via the Skill tool. When in doubt, invoke the skill.

Key routing rules:
- Product ideas/brainstorming → invoke /office-hours
- Strategy/scope → invoke /plan-ceo-review
- Architecture → invoke /plan-eng-review
- Design system/plan review → invoke /design-consultation or /plan-design-review
- Full review pipeline → invoke /autoplan
- Bugs/errors → invoke /investigate
- QA/testing site behavior → invoke /qa or /qa-only
- Code review/diff check → invoke /review
- Visual polish → invoke /design-review
- Ship/deploy/PR → invoke /ship or /land-and-deploy
- Code quality/health check → invoke /health
- Weekly retro/work review → invoke /retro
- Post-ship docs update → invoke /document-release
- Learnings verwalten → invoke /learn
- Save progress → invoke /context-save
- Resume context → invoke /context-restore

## Health Stack

- typecheck: cd frontend && npx tsc --noEmit
- lint-frontend: cd frontend && npx biome lint .
- lint-backend: cd backend && npx biome lint .
- test-frontend: cd frontend && npx vitest run
- test-backend: cd backend && node --test internal/*.test.js
