FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install uv for fast dependency resolution
RUN pip install uv

# Copy the entire workspace into /app
COPY . .

# Install the OpenEnv project itself
# The pyproject.toml correctly maps this root folder to the module name
RUN uv pip install --system -e .

EXPOSE 8000

CMD ["python", "-m", "soc_triage_env.server.app"]
