# Refactoring Project Folder Structure

The current folder structure is indeed a bit messy, with frontend and backend files mixed in the root directory alongside partially-used `frontend/` and `backend/` directories.

## Current State Observations:
1. **Frontend**: The React application is sitting in the root (`src/`, `public/`, `index.html`, `package.json`, `vite.config.js`), while an almost empty `frontend/` directory exists.
2. **Backend**: There is a `backend/` folder (with `routers/` and `services/`), but the main entry points (`main.py`, `vuln_analyzer.py`, `requirements.txt`) are floating in the root directory.
3. **Miscellaneous**: Various python scripts and markdown files are cluttering the root.

## Proposed Changes

We will reorganize the project into a clean monorepo structure with distinct `frontend` and `backend` directories.

### Root Directory Cleanup
Move all relevant files into their respective subdirectories. The root should only contain top-level configuration (e.g., `docker-compose.yml`, `README.md`, `.gitignore`).

#### [DELETE] Root Files & Folders (To be moved)
- `src/` (moving to `frontend/src/`)
- `public/` (moving to `frontend/public/`)
- `index.html` (moving to `frontend/`)
- `package.json` & `package-lock.json` (moving to `frontend/`)
- `vite.config.js` (moving to `frontend/`)
- `main.py` (moving to `backend/`)
- `vuln_analyzer.py` (moving to `backend/`)
- `requirements.txt` (moving to `backend/`)

### Frontend Refactoring
Move all React/Vite-related files into the `frontend/` directory.

#### [NEW] `frontend/`
- `src/`
- `public/`
- `index.html`
- `package.json`
- `package-lock.json`
- `vite.config.js`

### Backend Refactoring
Move all Python/FastAPI-related root files into the `backend/` directory.

#### [NEW] `backend/`
- `main.py`
- `vuln_analyzer.py`
- `requirements.txt`

### Docker Configuration Updates
Update the paths in `docker-compose.yml`, `Dockerfile.frontend`, and `Dockerfile.backend` to reflect the new file locations.

#### [MODIFY] `docker-compose.yml`
Update build contexts and volume mappings for the frontend and backend services.

#### [MODIFY] `Dockerfile.frontend` & `Dockerfile.backend`
Adjust `COPY` commands to work with the new structure.

## User Review Required

> [!WARNING]
> This refactor will move many files and modify the build configuration. Are you okay with me running these moves and updating the Dockerfiles/Docker Compose to match?

## Verification Plan

### Automated Tests
- Validate that `docker-compose up --build` successfully builds and starts the containers with the new structure.

### Manual Verification
- Check that the frontend is accessible on its assigned port.
- Check that the backend is accessible and responds to API calls.
