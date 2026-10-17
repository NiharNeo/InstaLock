FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml requirements.lock ./
COPY intentlock ./intentlock
COPY app ./app
COPY tools ./tools
RUN pip install --no-cache-dir -r requirements.lock && pip install --no-cache-dir --no-deps .
COPY alembic.ini ./
COPY migrations ./migrations
COPY policies ./policies
RUN useradd --uid 10001 --create-home gateway && mkdir /data && chown gateway /data
USER gateway
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
