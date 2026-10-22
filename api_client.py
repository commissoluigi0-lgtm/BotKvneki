from __future__ import annotations

import logging
import time
import httpx
import config

log = logging.getLogger(__name__)

class APIError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message

def _extract_error(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return f"HTTP {resp.status_code}"
    if isinstance(body, dict):
        for k in ("message", "error", "detail", "description"):
            if k in body and body[k]:
                return str(body[k])
    return f"HTTP {resp.status_code}"

class ShopAPI:
    def __init__(self):
        base = config.API_BASE_URL.rstrip("/") + "/"
        self._client = httpx.AsyncClient(
            base_url=base,
            headers={
                "X-Api-Key": config.API_KEY,
                "Accept": "application/json",
                "User-Agent": "SecureShopClient/2.0",
            },
            timeout=25.0,
        )
        self._search_cache = {}

    async def close(self):
        await self._client.aclose()

    def update_api_key(self, new_key: str):
        """Aggiorna la chiave API in tempo reale in memoria senza riavviare il processo."""
        config.API_KEY = new_key
        self._client.headers["X-Api-Key"] = new_key
        log.info("SIEM INFO | Chiave API Pre77 aggiornata dinamicamente in memoria.")

    async def _request(self, method: str, path: str, **kw):
        url = path.lstrip("/")
        try:
            resp = await self._client.request(method, url, **kw)
        except httpx.RequestError as e:
            raise APIError(500, f"Errore di rete: {e}")
        
        if resp.status_code == 401:
            log.critical("SIEM CRITICAL | La chiave API Pre77 è stata revocata o rifiutata dal server (HTTP 401)!")
            raise APIError(401, "Chiave API Pre77 scaduta, revocata o non valida. Usa /setkey per aggiornarla.")

        if resp.status_code >= 400:
            msg = _extract_error(resp)
            raise APIError(resp.status_code, msg)
        
        if resp.status_code == 204 or not resp.content:
            return {}
        
        try:
            return resp.json()
        except ValueError:
            return {}

    # ==================== ADMIN / PROFILE ====================
    async def get_me(self) -> dict:
        try:
            resp = await self._request("GET", "seller/v1/me")
            return resp
        except Exception as e:
            log.error("GET_ME FAILED: %s", e)
            try:
                resp = await self._request("GET", "me")
                return resp
            except Exception as e2:
                log.error("GET_ME FALLBACK FAILED: %s", e2)
                return {"balanceCents": 0}

    # ==================== WEBHOOKS (AUTOMATION) ====================
    async def get_webhook(self) -> dict:
        """Ottiene la configurazione attuale del webhook dal server Pre77."""
        return await self._request("GET", "webhooks")

    async def set_webhook(self, url: str, events: list[str] = None) -> dict:
        """Registra o aggiorna l'URL del webhook e gli eventi in ascolto."""
        if events is None:
            events = ["deposit.paid", "purchase.created", "cc.refunded", "shop.sold", "balance.changed"]
        payload = {
            "url": url,
            "events": events
        }
        return await self._request("PUT", "webhooks", json=payload)

    # ==================== SHOP API & DEPOSITS ====================
    async def cc_meta(self) -> dict:
        return await self._request("GET", "cc-shop/meta")

    async def cc_search(self, page: int = 1, page_size: int = 10, q: str = "", bins: str = "", sort: str = "price_asc", price_min=None, price_max=None, refund_allowed=None) -> dict:
        payload = {
            "page": page,
            "pageSize": page_size,
        }
        if q:
            payload["q"] = q
        if bins:
            payload["bins"] = bins
        if sort:
            payload["sort"] = sort
        if price_min is not None:
            payload["priceMin"] = price_min
        if price_max is not None:
            payload["priceMax"] = price_max
        if refund_allowed is not None:
            payload["refundAllowed"] = refund_allowed
            
        cache_key = str(payload)
        now = time.time()
        
        if cache_key in self._search_cache:
            cached_data, timestamp = self._search_cache[cache_key]
            if now - timestamp < 30:
                return cached_data

        result = await self._request("POST", "cc-shop/search", json=payload)
        self._search_cache[cache_key] = (result, now)
        return result

    async def cc_bin_lookup(self, bin_code: str) -> dict:
        """Verifica disponibilità e range di prezzo di un BIN (4-8 cifre)."""
        return await self._request("GET", f"cc-shop/bins/{bin_code}")

    async def cc_hold(self, card_ids: list[str]) -> dict:
        """Blocca le carte per 30 secondi (Hold) impedendo ad altri di acquistarle."""
        return await self._request("POST", "cc-shop/hold", json={"cardIds": card_ids})

    async def create_deposit_invoice(self, amount_cents: int, currency: str = "USDT") -> dict:
        """Crea un'invoice di deposito automatica sulla piattaforma Pre77 (Corretto da docs)."""
        payload = {
            "asset": currency,
            "amountCents": amount_cents
        }
        # Endpoint corretto secondo la documentazione Pre77: POST /wallet/deposit-orders
        res = await self._request("POST", "wallet/deposit-orders", json=payload)
        # La risposta restituisce un dizionario con la chiave "order"
        return res.get("order", res)

    async def get_deposit_status(self, invoice_id: str) -> dict:
        """Verifica lo stato di un'invoice di deposito creata (Corretto da docs)."""
        # Endpoint corretto secondo la documentazione Pre77: GET /wallet/deposit-orders/:id
        res = await self._request("GET", f"wallet/deposit-orders/{invoice_id}")
        return res.get("order", res)

    async def cc_get_cart(self) -> dict:
        return await self._request("GET", "cc-shop/cart")

    async def cc_add_cart(self, card_id: str) -> dict:
        return await self._request("POST", "cc-shop/cart", json={"cardId": card_id})

    async def cc_remove_cart(self, card_id: str) -> dict:
        return await self._request("DELETE", f"cc-shop/cart/{card_id}")

    async def cc_buy(self, card_ids: list[str], format_type: str = "") -> dict:
        payload = {"cardIds": card_ids}
        if format_type:
            payload["format"] = format_type
        return await self._request("POST", "cc-shop/buy", json=payload)

    async def cc_checkout(self) -> dict:
        return await self._request("POST", "cc-shop/checkout")

    async def cc_full_info(self, purchase_id: str) -> dict:
        return await self._request("POST", f"cc-shop/purchases/{purchase_id}/full-info")

    async def cc_check(self, purchase_id: str) -> dict:
        return await self._request("POST", f"cc-shop/purchases/{purchase_id}/check")

    async def cc_get_check(self, purchase_id: str, check_id: str) -> dict:
        return await self._request("GET", f"cc-shop/purchases/{purchase_id}/check/{check_id}")

    async def cc_refund(self, purchase_id: str, reason: str = "") -> dict:
        return await self._request("POST", f"cc-shop/purchases/{purchase_id}/refund", json={"reason": reason})

    async def cc_export_purchases(self) -> dict:
        return await self._request("GET", "cc-shop/purchases/export")

    async def cc_archive_purchase(self, purchase_id: str) -> dict:
        return await self._request("POST", f"cc-shop/purchases/{purchase_id}/archive")
