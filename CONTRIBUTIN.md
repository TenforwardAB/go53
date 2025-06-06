# Contributing to This Project

Thank you for your interest in contributing! This document will guide you through the contribution process and explain the Git workflow we use.

---

## Overview

We use a **Trunk-Based Development** workflow with **feature branches** and **pull requests (PRs)** to manage changes.

- The `main` branch is always stable and deployable.
- All development is done in short-lived branches created from `main`.
- Changes are merged into `main` via pull requests.
- Releases are tagged on `main`.

---

## Understanding the Workflow

### Trunk-Based Development (Simplified)

1. All work starts from the `main` branch.
2. You create a short-lived branch for your change (feature, fix, etc).
3. When done, you open a pull request (PR) into `main`.
4. The PR is reviewed, tested, and merged (usually with squash merge).
5. Tags are created for releases.

### Why This Workflow?

- Simple and intuitive for contributors
- Easy to review and test changes
- Keeps history clean and linear
- Avoids confusion with multiple long-lived branches

---

## How to Contribute

### 1. Fork the Repository

Use the "Fork" button on GitHub to fork the repo into your account.

### 2. Clone Your Fork

```bash
git clone https://github.com/YOUR_USERNAME/PROJECT_NAME.git
cd PROJECT_NAME
```

### 3. Create a Branch

```bash
git checkout -b feat/your-feature-name
```

Use a clear and descriptive branch name, e.g.:

- `feat/login-form`
- `fix/typo-in-readme`
- `chore/update-deps`

### 4. Make Your Changes

Make commits with meaningful messages:

```bash
git commit -m "Add login button to header"
```

### 5. Push Your Branch

```bash
git push origin feat/your-feature-name
```

### 6. Open a Pull Request

- Go to your fork on GitHub
- Click "Compare & Pull Request"
- Fill out the PR template
- Select `main` as the base branch

---

## Labels We Use

We use GitHub labels to guide contributors:

- `good first issue`: Great for newcomers
- `help wanted`: We need help on this
- `bug`: Something is broken
- `enhancement`: New feature or improvement
- `documentation`: Docs-only changes
- `wontfix`: Closed but not fixed
- `in progress`: Being actively worked on
- `discussion`: Needs more input

---

## Tests & Linting

Make sure all tests pass before submitting a PR.

---

## Code of Conduct

Be respectful, collaborative, and constructive. This project follows the [Contributor Covenant](https://www.contributor-covenant.org/) Code of Conduct.

---

## Maintainer Tips

- PRs should be small and focused
- We prefer squash merges to keep history clean
- Automated CI must pass for a PR to be merged

---

## Need Help?

Open an issue or start a discussion! We’re happy to help.

Happy coding! 