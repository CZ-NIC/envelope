# Releasing: write the changes under a "## Unreleased" heading in CHANGELOG.md, then either
#   make release-with-commit PART=patch|minor|major   bump, commit "chore(release): X", tag, push both
#   make bump PART=…   only edit the files, commit them yourself, then: make release   check, tag, push the tag
# Bump, commit and tag: [tool.bumpversion] in pyproject.toml. The tag push triggers CI: PyPI + GitHub release.
.PHONY: release-with-commit bump release
BMV := .release-venv/bin/bump-my-version
V = $$($(BMV) show current_version)
# Release exactly what is on origin/main: clean tree, on main, nothing unpushed.
PREFLIGHT = git diff --quiet HEAD && test "$$(git branch --show-current)" = main && git fetch -q origin main && test "$$(git rev-parse HEAD)" = "$$(git rev-parse origin/main)"

release-with-commit: $(BMV)
	$(PREFLIGHT)
	$(BMV) bump $(PART)
	git push --atomic origin main $(V)

bump: $(BMV)
	$(BMV) bump $(PART) --no-commit --no-tag --allow-dirty

## Tag a clean, pushed commit whose pyproject and CHANGELOG hold the current version.
release: $(BMV)
	$(PREFLIGHT)
	grep -q '^version = "'$(V)'"' pyproject.toml && grep -q '^## '$(V)' (' CHANGELOG.md
	git tag -a $(V) -m $(V)
	git push origin $(V)

$(BMV):
	python3 -m venv .release-venv && .release-venv/bin/pip install -q "bump-my-version>=1.3"
