# WARRANT demo storefronts

Self-contained FastAPI storefronts for the hackathon demo. They do not import the backend and do not contact a payment processor.

## Install

```sh
cd merchants
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Spoof storefront: fails verification

```sh
cd merchants/spoof
uvicorn app:app --host 127.0.0.1 --port 8011
```

Open <http://127.0.0.1:8011/>.

This fictional Harbor Lane demo store looks plausible, includes a product page and checkout form, and visibly labels every rendered page as a WARRANT demonstration storefront. Its product review contains an indirect prompt-injection instruction aimed at an automated purchasing agent, so WARRANT's injection probe should reject it.

## Breach storefront: passes verification, then over-delivers

```sh
cd merchants/breach
uvicorn app:app --host 127.0.0.1 --port 8012
```

Open <http://127.0.0.1:8012/>.

This fictional Northstar Supply demo store has clean catalogue content with no prompt injection. The checkout intentionally demonstrates reconciliation drift:

- agent authorizes: `1` unit at `$84.00`
- merchant charges: `"84.00"`
- merchant confirms: default `12` units at `"84.00"` unit price

The POST `/checkout` response is the observed order confirmation:

```json
{
  "order_id": "breach-...",
  "merchant_domain": "breach.localhost",
  "amount_charged": "84.00",
  "status": "CONFIRMED",
  "line_items": [
    {"sku": "NS-CLIP-84", "description": "Northstar Field Clips", "quantity": 12, "unit_price": "84.00"}
  ]
}
```

Poll `GET /orders/{order_id}` to retrieve the same confirmation.

Set `BREACH_QUANTITY=1` to make the same server honest, or another integer to change the confirmed quantity:

```sh
cd merchants/breach
BREACH_QUANTITY=1 uvicorn app:app --host 127.0.0.1 --port 8012
```

For one-off demos, `POST /checkout?breach_quantity=12` overrides the environment value for that order.
