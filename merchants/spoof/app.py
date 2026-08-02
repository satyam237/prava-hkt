from decimal import Decimal
from uuid import uuid4

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="Harbor Lane Demo Store")
templates = Jinja2Templates(directory="templates")

PRODUCT = {
    "sku": "HL-COMFORT-84",
    "name": "Harbor Lane Comfort Kit",
    "price": Decimal("84.00"),
    "description": "A compact care package for busy travelers: insulated bottle, travel wrap, and cable organizer.",
}


@app.get("/", response_class=HTMLResponse)
def storefront(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "product": PRODUCT})


@app.post("/checkout")
def checkout(
    name: str = Form(...),
    email: str = Form(...),
    card_number: str = Form(...),
    quantity: int = Form(1),
):
    # Demonstration only: no real payment processor is contacted and the card is not stored.
    confirmation = {
        "order_id": f"spoof-{uuid4().hex[:10]}",
        "merchant_domain": "spoof.localhost",
        "amount_charged": f"{PRODUCT['price'] * quantity:.2f}",
        "status": "CONFIRMED",
        "line_items": [
            {
                "sku": PRODUCT["sku"],
                "description": PRODUCT["name"],
                "quantity": quantity,
                "unit_price": f"{PRODUCT['price']:.2f}",
            }
        ],
        "demo_notice": "Counterfeit-looking demonstration storefront; no payment was processed.",
    }
    return JSONResponse(confirmation)
