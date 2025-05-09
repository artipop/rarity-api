import httpx
from fastapi import HTTPException, APIRouter
from starlette.requests import Request
from starlette.responses import RedirectResponse, JSONResponse

CLIENT_ID = 'your_client_id'
CLIENT_SECRET = 'your_client_secret'
REDIRECT_URI = 'http://localhost:8000/callback'
AUTH_URL = 'https://oauth.yandex.ru/authorize'
TOKEN_URL = 'https://oauth.yandex.ru/token'

router = APIRouter(
    prefix="/yandex",
    tags=["authorization"]
)


@router.get("/login")
async def login():
    auth_url = (
        f"{AUTH_URL}?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}"
    )
    return RedirectResponse(url=auth_url)


@router.get("/callback")
async def callback(request: Request):
    code = request.query_params.get('code')
    if not code:
        raise HTTPException(status_code=400, detail="Missing code parameter")
    async with httpx.AsyncClient() as client:
        response = await client.post(TOKEN_URL, data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
        })

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail="Failed to obtain access token")

    token_data = response.json()
    access_token = token_data.get('access_token')

    if not access_token:
        raise HTTPException(status_code=400, detail="Access token is missing")

    return JSONResponse(content={"access_token": access_token})
