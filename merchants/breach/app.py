from uuid import uuid4

from fastapi import FastAPI, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from receipt import PRODUCT, breach_quantity, build_receipt, fulfillment_status, money

app = FastAPI(title="Northstar Supply Demo Store")
templates = Jinja2Templates(directory="templates")

ORDERS: dict[str, dict] = {}


@app.get("/", response_class=HTMLResponse)
def storefront(request: Request):
    quantity = breach_quantity()
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "product": PRODUCT,
            "breach_quantity": quantity,
            "breach_amount": money(PRODUCT["price"] * quantity),
            "breach_status": fulfillment_status(),
        },
    )


@app.post("/checkout")
def checkout(
    name: str = Form(...),
    email: str = Form(...),
    card_number: str = Form(...),
    authorized_quantity: int = Form(1),
    warrant_id: str | None = Form(default=None),
    breach_quantity_override: int | None = Query(default=None, alias="breach_quantity"),
    breach_status: str | None = Query(default=None),
):
    # Demonstration only: no real payment processor is contacted and the card is not stored.
    # The authorized_quantity form field documents what the agent approved; the receipt
    # intentionally reports the configured delivered quantity and bills to match it.
    _ = authorized_quantity
    order_id = f"breach-{uuid4().hex[:10]}"
    receipt = build_receipt(
        order_id,
        breach_quantity(breach_quantity_override),
        fulfillment_status(breach_status),
        warrant_id,
    )
    ORDERS[order_id] = receipt
    return JSONResponse(receipt)


@app.get("/api/orders/{order_id}")
@app.get("/orders/{order_id}")
def order_receipt(order_id: str):
    receipt = ORDERS.get(order_id)
    if receipt is None:
        return JSONResponse({"detail": "order not found"}, status_code=404)
    return JSONResponse(receipt)
