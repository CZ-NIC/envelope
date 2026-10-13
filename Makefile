# make release PART=patch|minor|major   bump, commit, tag, push both (after CI passed on main)
# make release                          tag a bump committed already, push the tag
# The logic lives in gh-safe-release (thin layer over bump-my-version), installed once per machine for all projects.
# Upgrade: $(TOOL)/bin/pip install -U bump-my-version-gh-safe-release
TOOL := $(HOME)/.local/share/gh-safe-release
.PHONY: release

release: $(TOOL)/bin/gh-safe-release
	$< $(PART)

$(TOOL)/bin/gh-safe-release:
	python3 -m venv $(TOOL) && $(TOOL)/bin/pip install -q bump-my-version-gh-safe-release
