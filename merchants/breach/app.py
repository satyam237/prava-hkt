import os
from decimal import Decimal
from uuid import uuid4

from fastapi import FastAPI, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="Northstar Supply Demo Store")
templates = Jinja2Templates(directory="templates")

PRODUCT = {
    "sku": "NS-CLIP-84",
    "name": "Northstar Field Clips",
    "price": Decimal("84.00"),
    "authorized_quantity": 1,
}
ORDERS: dict[str, dict] = {}


def _breach_quantity(override: int | None = None) -> int:
    if override is not None:
        return max(1, override)
    raw = os.getenv("BREACH_QUANTITY", "12")
    try:
        return max(1, int(raw))
    except ValueError:
        return 12


def _confirmation(order_id: str, delivered_quantity: int) -> dict:
    return {
        "order_id": order_id,
        "merchant_domain": "breach.localhost",
        "amount_charged": "84.00",
        "status": "CONFIRMED",
        "line_items": [
            {
                "sku": PRODUCT["sku"],
                "description": PRODUCT["name"],
                "quantity": delivered_quantity,
                "unit_price": "84.00",
            }
        ],
    }


@app.get("/", response_class=HTMLResponse)
def storefront(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "product": PRODUCT, "breach_quantity": _breach_quantity()},
    )


@app.post("/checkout")
def checkout(
    name: str = Form(...),
    email: str = Form(...),
    card_number: str = Form(...),
    authorized_quantity: int = Form(1),
    breach_quantity: int | None = Query(default=None),
):
    # Demonstration only: no real payment processor is contacted and the card is not stored.
    # The authorized_quantity form field documents what the agent approved; the confirmation
    # intentionally reports the configured delivered quantity while keeping the charge at $84.00.
    _ = authorized_quantity
    order_id = f"breach-{uuid4().hex[:10]}"
    delivered_quantity = _breach_quantity(breach_quantity)
    confirmation = _confirmation(order_id, delivered_quantity)
    ORDERS[order_id] = confirmation
    return JSONResponse(confirmation)


@app.get("/orders/{order_id}")
def order_status(order_id: str):
    confirmation = ORDERS.get(order_id)
    if confirmation is None:
        return JSONResponse({"detail": "order not found"}, status_code=404)
    return JSONResponse(confirmation)
