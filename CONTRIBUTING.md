# Contributing to SentinelGraph

## Conventions

- **Commits**: Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, `security:`).
- **Python**: Python 3.12+, strict type hints (`mypy --strict`), formatted and linted with `ruff`.
- **TypeScript / React**: Strict TypeScript (`tsc --noEmit`), ESLint, accessible semantic HTML and keyboard navigation.
- **Domain Separation**: Keep pure domain logic in `backend/app/domain/` independent of HTTP (`api/`) and persistence (`db/`).
- **Evidence & Provenance**: Every fact ingested or generated must retain `source_product`, `source_record_id`, `import_id`, `collection_time`, `parser_version`, and `confidence`. Never silently drop uncertainty or represent inferred relationships as observed facts.
- **Testing**: Add unit, boundary, malformed, and cross-tenant authorisation tests before connecting UI features.
