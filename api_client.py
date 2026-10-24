from __future__ import annotations
import aiohttp
import logging
import config

log = logging.getLogger(__name__)

class APIError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)

class ShopAPI:
    def __init__(self):
        self.base_url = config.API_BASE_URL
        self.api_key = config.PRE77_API_KEY
        self.headers = {
            "X-Api-Key": self.api_key,
            "Content-Type": "application/json"
        }

    def update_api_key(self, new_key: str):
        self.api_key = new_key
        self.headers["X-Api-Key"] = new_key

    async def _request(self, method: str, endpoint: str, data: dict = None) -> dict:
        url = f"{self.base_url}{endpoint}"
        async with aiohttp.ClientSession(headers=self.headers) as session:
            try:
                async with session.request(method, url, json=data) as resp:
                    resp_data = await resp.json()
                    if not resp.ok:
                        raise APIError(resp_data.get("error", f"Errore HTTP {resp.status}"))
                    return resp_data
            except aiohttp.ClientError as e:
                log.error("Errore di connessione API: %s", e)
                raise APIError("Errore di connessione al provider.")

    async def get_me(self) -> dict:
        # Recupera i metadati e il saldo (simulato se l'endpoint specifico manca nei doc base, 
        # pre77 di solito lo fornisce in un endpoint me o meta)
        return await self._request("GET", "/cc-shop/meta")

    async def cc_search(self, page: int = 1, page_size: int = 20, q: str = "", sort: str = "price_asc") -> dict:
        payload = {
            "page": page,
            "pageSize": page_size,
            "sort": sort,
            "q": q,
            "filter": {}
        }
        return await self._request("POST", "/cc-shop/search", data=payload)

    async def cc_get_cart(self) -> dict:
        return await self._request("GET", "/cc-shop/cart")

    async def cc_add_cart(self, card_id: str) -> dict:
        return await self._request("POST", "/cc-shop/cart", data={"cardId": card_id})

    async def cc_remove_cart(self, card_id: str) -> dict:
        return await self._request("DELETE", f"/cc-shop/cart/{card_id}")

    async def cc_checkout(self) -> dict:
        return await self._request("POST", "/cc-shop/checkout")

    async def cc_reveal(self, purchase_id: str) -> dict:
        return await self._request("POST", f"/cc-shop/purchases/{purchase_id}/full-info")
        
    async def cc_check(self, purchase_id: str) -> dict:
        return await self._request("POST", f"/cc-shop/purchases/{purchase_id}/check")
