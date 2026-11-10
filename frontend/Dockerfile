# Frontend DEVELOPMENT image (Vite dev server). It is not a production web server: use `npm run build` and serve dist/ for that.
# Base image: Node 24 (Active LTS). Node 18 reached end-of-life in April 2025.
# Not built in the environment where it was written (Docker was not available there).
FROM node:24-alpine

WORKDIR /app

# WORKDIR creates /app as root. Hand it to the unprivileged node user BEFORE anything is installed, so that npm ci and the
# Vite dependency cache (node_modules/.vite) are written by node. Nothing after this line runs as root.
RUN chown node:node /app

USER node

COPY --chown=node:node package.json package-lock.json ./
# npm ci installs exactly what the lockfile records
RUN npm ci

COPY --chown=node:node . .

EXPOSE 5173

CMD ["npm", "run", "dev", "--", "--host"]
