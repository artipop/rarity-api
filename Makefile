dev:
	poetry run uvicorn main:app --host 0.0.0.0 --reload --app-dir src/rarity_api

kill:
	taskkill /f /im python.exe

rev:
	poetry run alembic revision --autogenerate

mig:
	poetry run alembic upgrade head
