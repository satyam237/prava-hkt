"""The order receipt this demo merchant issues, and the knobs that shape it.

Kept free of any web framework so it is importable on its own: this is the
observed side of reconciliation, and the backend's test suite asserts against
the merchant's real receipt rather than a hand-copied fixture that can drift.

Money is built with ``Decimal`` and leaves as a two-decimal string. Nothing here
produces a float, because a float is what the reconciler refuses to accept.
"""

import os
from datetime import datetime, timezone
from decimal import Decimal

MERCHANT_DOMAIN = "breach.localhost"
CURRENCY = "USD"

PRODUCT = {
    "sku": "NS-CLIP-84",
    "name": "Northstar Field Clips",
    "price": Decimal("84.00"),
    "authorized_quantity": 1,
}

#: The two statuses the reconciler reads as an observation of fulfillment.
#: They drive the settled path and the non-delivery path respectively.
FULFILLED = "FULFILLED"
UNFULFILLED = "UNFULFILLED"

DEFAULT_BREACH_QUANTITY = 12

DEMO_NOTICE = "Demonstration storefront operated by the WARRANT project; no payment was processed."


def money(value: Decimal) -> str:
    return f"{value:.2f}"


def breach_quantity(override: int | None = None) -> int:
    """How many units this merchant will claim it shipped and billed for.

    ``1`` makes the same server honest, which is the SETTLED demo; the default
    ``12`` against a warrant for one unit is the breach.
    """
    if override is not None:
        return max(1, override)
    try:
        return max(1, int(os.getenv("BREACH_QUANTITY", str(DEFAULT_BREACH_QUANTITY))))
    except ValueError:
        return DEFAULT_BREACH_QUANTITY


def fulfillment_status(override: str | None = None) -> str:
    raw = (override or os.getenv("BREACH_STATUS", FULFILLED)).upper()
    return raw if raw in {FULFILLED, UNFULFILLED} else FULFILLED


def build_receipt(
    order_id: str,
    quantity: int,
    status: str,
    warrant_id: str | None = None,
    now: datetime | None = None,
) -> dict:
    """What this merchant claims it actually fulfilled and billed.

    The quantity and the amount move together: over-delivering twelve units
    means billing for twelve, so the default receipt reads 12 x 84.00 =
    1008.00 against a warrant authorizing one unit at 84.00.

    This, not Prava's payment result, is the honest observed side. Prava's
    result echoes back the purchase context the agent sent it; only the
    merchant knows what left the warehouse.
    """
    unit_price = PRODUCT["price"]
    total = unit_price * quantity
    at = now or datetime.now(timezone.utc)
    return {
        "order_id": order_id,
        "warrant_id": warrant_id,
        "merchant_domain": MERCHANT_DOMAIN,
        "status": status,
        "currency": CURRENCY,
        "amount_charged": money(total),
        "fulfilled_at": at.strftime("%Y-%m-%dT%H:%M:%SZ") if status == FULFILLED else None,
        "line_items": [
            {
                "sku": PRODUCT["sku"],
                "description": PRODUCT["name"],
                "quantity": quantity,
                "unit_price": money(unit_price),
                "line_total": money(total),
            }
        ],
        "demo_notice": DEMO_NOTICE,
    }
