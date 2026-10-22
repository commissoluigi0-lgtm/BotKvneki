from __future__ import annotations

import logging
import aiohttp
from typing import Any, Dict

log = logging.getLogger(__name__)

class APIError(Exception):
    def __init__(self, message: str, status: int = 400):
        self.message = message
        self.status = status
        super().__init__(message)

class ShopAPI:
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or getattr(config, "PRE77_API_KEY", "")
        self.base_url = "https://pre77.to/api/seller/v1"
        self.session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            headers = {
                "X-Api-Key": self.api_key,
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            self.session = aiohttp.ClientSession(headers=headers)
        return self.session

    def update_api_key(self, new_key: str):
        self.api_key = new_key
        if self.session and not self.session.closed:
            # Forzeremo il rinnovo della sessione con i nuovi header
            pass

    async def _request(self, method: str, endpoint: str, **kwargs) -> Any:
        session = await self._get_session()
        url = f"{self.base_url}{endpoint}"
        try:
            async with session.request(method, url, **kwargs) as resp:
                data = await resp.json()
                if resp.status >= 400:
                    msg = data.get("error", data.get("message", "API Error"))
                    raise APIError(msg, resp.status)
                return data
        except aiohttp.ClientError as e:
            log.error("Errore di connessione API Pre77: %s", e)
            raise APIError("Impossibile connettersi al server Pre77", 503)

    async def get_me(self) -> Dict[str, Any]:
        return await self._request("GET", "/me")

    async def get_shop(self) -> Dict[str, Any]:
        return await self._request("GET", "/shop")

    async def get_shop_stock(self, product_id: str) -> Dict[str, Any]:
        """Ottiene lo stock dettagliato (used/unused lines) di un prodotto."""
        return await self._request("GET", f"/shop/products/{product_id}/stock")

    async def restock_product(self, product_id: str, delivery_lines_text: str) -> Dict[str, Any]:
        """Aggiunge nuove linee di consegna (restock) a un prodotto."""
        return await self._request("POST", f"/shop/products/{product_id}/restock", json={"deliveryLinesText": delivery_lines_text})

    async def set_webhook(self, url: str) -> Dict[str, Any]:
        return await self._request("PUT", "/webhooks", json={"url": url, "events": ["deposit.paid", "purchase.created", "cc.refunded", "shop.sold", "balance.changed"]})

    async def cc_search(self, **kwargs) -> Dict[str, Any]:
        return await self._request("POST", "/cc-shop/search", json=kwargs)

    async def cc_add_cart(self, card_id: str) -> Dict[str, Any]:
        return await self._request("POST", "/cc-shop/cart", json={"cardId": card_id})

    async def cc_get_cart(self) -> Dict[str, Any]:
        return await self._request("GET", "/cc-shop/cart")

    async def cc_remove_cart(self, card_id: str) -> Dict[str, Any]:
        return await self._request("DELETE", f"/cc-shop/cart/{card_id}")

    async def cc_checkout(self) -> Dict[str, Any]:
        return await self._request("POST", "/cc-shop/checkout")

    async def cc_hold(self, card_ids: list) -> Dict[str, Any]:
        return await self._request("POST", "/cc-shop/hold", json={"cardIds": card_ids})

    async def cc_buy(self, card_ids: list, format_type: str = "txt") -> Dict[str, Any]:
        return await self._request("POST", "/cc-shop/buy", json={"cardIds": card_ids, "format": format_type})

    async def cc_full_info(self, purchase_id: str) -> Dict[str, Any]:
        res = await self._request("POST", f"/cc-shop/purchases/{purchase_id}/full-info")
        return res.get("card", res)

    async def cc_check(self, purchase_id: str) -> Dict[str, Any]:
        return await self._request("POST", f"/cc-shop/purchases/{purchase_id}/check")

    async def cc_get_check(self, purchase_id: str, check_id: str) -> Dict[str, Any]:
        return await self._request("GET", f"/cc-shop/purchases/{purchase_id}/check/{check_id}")

    async def cc_refund(self, purchase_id: str, reason: str = "declined") -> Dict[str, Any]:
        return await self._request("POST", f"/cc-shop/purchases/{purchase_id}/refund", json={"reason": reason})

    async def cc_export_purchases(self) -> Any:
        # Ritorna il dump in formato testo
        session = await self._get_session()
        async with session.get(f"{self.base_url}/cc-shop/purchases/export") as resp:
            return {"dump": await resp.text()}

    async def get_deposit_assets(self) -> Dict[str, Any]:
        return await self._request("GET", "/wallet/deposit-assets")

    async def create_deposit_invoice(self, amount_cents: int, currency: str) -> Dict[str, Any]:
        return await self._request("POST", "/wallet/deposit-orders", json={"asset": currency, "amountCents": amount_cents})

    async def get_deposit_status(self, order_id: str) -> Dict[str, Any]:
        res = await self._request("GET", f"/wallet/deposit-orders/{order_id}")
        return res.get("order", res)

    async def cc_bin_lookup(self, bin_code: str) -> Dict[str, Any]:
        return await self._request("GET", f"/cc-shop/bins/{bin_code}")

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
