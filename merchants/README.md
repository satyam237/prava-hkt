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

This fictional Northstar Supply demo store has clean catalogue content with no prompt injection. It passes verification and then over-delivers:

- agent authorizes: `1` unit at `$84.00`
- merchant ships and bills: default `12` units at `$1,008.00`

### The order receipt

`GET /api/orders/{order_id}` (also served at `GET /orders/{order_id}`, and returned directly from `POST /checkout`) is the merchant's own claim about what it fulfilled and billed:

```json
{
  "order_id": "breach-9f2c1a",
  "warrant_id": "wrt_...",
  "merchant_domain": "breach.localhost",
  "status": "FULFILLED",
  "currency": "USD",
  "amount_charged": "1008.00",
  "fulfilled_at": "2026-08-02T21:14:03Z",
  "line_items": [
    {
      "sku": "NS-CLIP-84",
      "description": "Northstar Field Clips",
      "quantity": 12,
      "unit_price": "84.00",
      "line_total": "1008.00"
    }
  ],
  "demo_notice": "..."
}
```

**This is the observed side of reconciliation, and the only honest source of it.** Prava's payment result echoes back the `purchase_context` the agent submitted at session creation, so diffing a warrant against it compares a document to itself. Prava issues the payment token; only the merchant knows what left the warehouse. `backend/app/reconcile.py` folds this receipt into an `Outcome` and diffs it against the signed warrant.

Every amount is a decimal string. Nothing in the receipt is a float — the reconciler rejects one, because float text formatting is language-specific and these values end up inside a signed document.

### Switching the demo path

| Setting | Result |
|---|---|
| default | `12` units at `1008.00` → `BREACH` with `AMOUNT_EXCEEDED` + `QUANTITY_MISMATCH` |
| `BREACH_QUANTITY=1` | `1` unit at `84.00` → `SETTLED` |
| `BREACH_STATUS=UNFULFILLED` | `fulfilled_at: null` → `NON_DELIVERY` once the warrant's deadline passes |

```sh
cd merchants/breach
BREACH_QUANTITY=1 uvicorn app:app --host 127.0.0.1 --port 8012
```

For one-off demos, `POST /checkout?breach_quantity=12&breach_status=UNFULFILLED` overrides both for that order.

`receipt.py` holds the receipt contract and imports nothing but the standard library, so the backend test suite loads it directly and asserts against the merchant's real output rather than a copied fixture.
