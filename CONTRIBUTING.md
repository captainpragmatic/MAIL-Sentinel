# Contributing to M.A.I.L. Sentinel

Thank you for your interest in contributing!

## How to Contribute

- Fork and clone the repository.
- Create a feature branch with a descriptive name.
- Add tests or improvements, and ensure your changes pass ShellCheck.
- Submit a pull request with clear descriptions of your changes.

## Development Setup

There are two ways to set up automatic ShellCheck validation before commits:

### Option 1: Simple Git Hook (Lightweight)

Create a local `.git/hooks/pre-commit` script that runs shellcheck directly. This is simple but only exists locally and doesn't sync across the team.

#### Installation

1. Create the pre-commit hook file:
   ```bash
   cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash

# Run ShellCheck on all staged .sh and .bash files
for file in $(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(sh|bash)$'); do
  if [ -f "$file" ]; then
    shellcheck -S warning "$file"
    if [ $? -ne 0 ]; then
      echo "ShellCheck failed for $file"
      exit 1
    fi
  fi
done
EOF
   ```

2. Make it executable:
   ```bash
   chmod +x .git/hooks/pre-commit
   ```

**Note:** This hook is stored in `.git/hooks/` which is not tracked by version control, so each contributor would need to set it up manually.

### Option 2: Pre-commit Framework (Recommended)

This project uses [pre-commit](https://pre-commit.com/) to automatically run ShellCheck and other checks before each commit. This catches issues early and ensures consistency with CI/CD checks.

#### Installation

1. Install pre-commit (if not already installed):
   ```bash
   # Using pip
   pip install pre-commit

   # Using Homebrew (macOS)
   brew install pre-commit

   # Using conda
   conda install -c conda-forge pre-commit
   ```

2. Install the git hook scripts:
   ```bash
   pre-commit install
   ```

3. (Optional) Run against all files to verify setup:
   ```bash
   pre-commit run --all-files
   ```

#### What Gets Checked

The pre-commit hooks will automatically run:
- **ShellCheck**: Lints all `.sh` and `.bash` files
- **Check for large files**: Prevents accidentally committing files >500KB
- **Check for merge conflicts**: Detects merge conflict markers
- **End of file fixer**: Ensures files end with a newline
- **Trailing whitespace**: Removes trailing whitespace

If any check fails, the commit will be blocked and you'll see the errors that need to be fixed.

#### Updating Hooks

To update the pre-commit hooks to the latest versions:
```bash
pre-commit autoupdate
```

## Code Style

- Use ShellCheck for linting your bash scripts.
- Keep modifications clear and small.

Happy coding!
