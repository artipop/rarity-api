dev:
	poetry run uvicorn main:app --host 0.0.0.0 --reload --app-dir src/rarity_api

kill:
	taskkill /f /im python.exe

rev:
	poetry run alembic revision --autogenerate

mig:
	poetry run alembic upgrade head

excel:
	poetry run python src/excel_parser.py

csv:
	poetry run python src/excel_parser_second.py

deployd:
	docker compose --env-file .env up --build -d

deploy:
	docker compose --env-file .env up --build

symbol:
	poetry run python src/symbols_parser.py