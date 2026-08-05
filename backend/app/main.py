import hashlib
import base64
import os
import re
import secrets
import tempfile
from typing import Any
from uuid import UUID, uuid4

import psycopg
import requests
from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel

from .db import execute, fetch_all, fetch_one
from .config import settings
from .security import require_token

API_VERSION = "1.0.31"

app = FastAPI(title="Licensafe API", version=API_VERSION)


@app.on_event("startup")
def ensure_runtime_schema() -> None:
    statements = [
        "alter table products add column if not exists stock_quantity numeric(12,3) not null default 0",
        "alter table billing_invoices add column if not exists issued_by_id uuid references app_users(id)",
        "alter table billing_invoices add column if not exists issued_by_name text",
        "alter table billing_invoices add column if not exists issued_at timestamptz",
        "alter table billing_invoices add column if not exists cancelled_by_id uuid references app_users(id)",
        "alter table billing_invoices add column if not exists cancelled_by_name text",
        "alter table billing_invoices add column if not exists cancelled_at timestamptz",
        "alter table billing_invoices add column if not exists cancellation_reason text",
        "alter table fiscal_invoices add column if not exists issued_by_id uuid references app_users(id)",
        "alter table fiscal_invoices add column if not exists issued_by_name text",
        "alter table fiscal_invoices add column if not exists issued_at timestamptz",
        "alter table fiscal_invoices add column if not exists cancelled_by_id uuid references app_users(id)",
        "alter table fiscal_invoices add column if not exists cancelled_by_name text",
        "alter table fiscal_invoices add column if not exists cancellation_protocol text",
        "alter table fiscal_invoices add column if not exists sefaz_return text",
        "alter table fiscal_invoices add column if not exists xml_content text",
    ]
    for statement in statements:
        execute(statement)


class CustomerIn(BaseModel):
    id: str | None = None
    local_id: int | None = None
    name: str
    trade_name: str | None = None
    document: str | None = None
    state_registration: str | None = None
    address: str | None = None
    phone: str | None = None
    whatsapp: str | None = None
    email: str | None = None
    business_license_expiration: str | None = None
    notes: str | None = None
    active: bool = True


class ProductIn(BaseModel):
    local_id: int | None = None
    code: str
    description: str
    category: str | None = None
    unit: str = "UN"
    price: float = 0
    cost: float | None = None
    stock_quantity: float = 0
    ncm: str | None = None
    cfop: str | None = None
    cest: str | None = None
    origin: str | None = "0"
    cst_csosn: str | None = None
    icms_rate: float = 0
    pis_rate: float = 0
    cofins_rate: float = 0
    active: bool = True


class UserIn(BaseModel):
    local_id: int | None = None
    name: str
    email: str
    password_hash: str | None = None
    password: str | None = None
    role: str
    active: bool = True


class LoginIn(BaseModel):
    email: str
    password: str


class OrderItemIn(BaseModel):
    local_id: int | None = None
    product_id: str | None = None
    product_local_id: int | None = None
    code: str
    description: str
    unit: str = "UN"
    quantity: float
    unit_price: float


class OrderIn(BaseModel):
    local_id: int | None = None
    number: int | None = None
    customer_id: str | None = None
    customer_local_id: int | None = None
    customer_document: str | None = None
    customer_name: str
    seller_id: str | None = None
    seller_local_id: int | None = None
    seller_email: str | None = None
    seller_name: str
    discount_type: str = "value"
    discount: float = 0
    payment_type: str = "cash"
    cash_payment_method: str = "money"
    credit_card_installments: int = 1
    credit_card_fee_percent: float = 0
    boleto_terms: str = ""
    extinguisher_validity: str | None = None
    subtotal: float = 0
    total: float = 0
    notes: str | None = None
    status: str = "finished"
    items: list[OrderItemIn]


class FiscalIssueIn(BaseModel):
    series: int = 1
    environment: str = "producao"
    status: str = "pending"
    message: str | None = None


class BillingIn(BaseModel):
    local_id: int | None = None
    order_id: str | None = None
    order_local_id: int | None = None
    order_number: int
    customer_id: str | None = None
    customer_local_id: int | None = None
    customer_name: str
    amount: float
    due_date: str
    status: str = "open"
    cora_id: str | None = None
    cora_code: str | None = None
    bank_slip_url: str | None = None
    digitable_line: str | None = None
    barcode: str | None = None
    pix_copy_paste: str | None = None
    issued_by_name: str | None = None
    issued_at: str | None = None
    cancelled_by_name: str | None = None
    cancelled_at: str | None = None
    cancellation_reason: str | None = None


class BillingCancelIn(BaseModel):
    reason: str | None = None


@app.get("/health")
def health():
    row = fetch_one("select now() as now")
    return {"ok": True, "api_version": API_VERSION, "database_time": row["now"]}


@app.post("/auth/login")
def login(payload: LoginIn) -> dict[str, Any]:
    password_hash = _hash_password(payload.password)
    user = fetch_one(
        """
        select id, local_id, name, email, role, active, password_hash
        from app_users
        where lower(email) = lower(%s) and password_hash = %s and deleted_at is null
        limit 1
        """,
        (payload.email.strip(), password_hash),
    )
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="E-mail ou senha invalidos.")
    if user["active"] is False:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=" usuario inativo entrar em contato com o Administrador ")
    session_token = _create_mobile_session(str(user["id"]))
    safe_user = {key: value for key, value in user.items() if key != "password_hash"}
    return {"ok": True, "user": safe_user, "session_token": session_token}


@app.get("/customers", dependencies=[Depends(require_token)])
def customers(updated_after: str | None = None):
    if updated_after:
        return fetch_all(
            "select * from customers where updated_at > %s order by updated_at asc",
            (updated_after,),
        )
    return _customers_without_duplicates()


@app.get("/customers/deleted", dependencies=[Depends(require_token)])
def deleted_customers() -> list[dict[str, Any]]:
    return fetch_all(
        """
        select id, local_id, document, updated_at, deleted_at
        from customers
        where deleted_at is not null
        order by updated_at desc
        """
    )


@app.post("/sync/customers", dependencies=[Depends(require_token)])
def sync_customers(items: list[CustomerIn]) -> dict[str, Any]:
    try:
        for item in items:
            _save_customer(item)
    except psycopg.Error as error:
        raise HTTPException(status_code=400, detail=f"Erro ao sincronizar cliente: {error}") from error
    return {"ok": True, "count": len(items)}


@app.post("/sync/users", dependencies=[Depends(require_token)])
def sync_users(items: list[UserIn]) -> dict[str, Any]:
    try:
        for item in items:
            execute(
                """
                insert into app_users (
                  local_id, name, email, password_hash, role, active, updated_at
                )
                values (%s,%s,lower(%s),%s,%s,%s,now())
                on conflict (email) do update set
                  local_id = excluded.local_id,
                  name = excluded.name,
                  password_hash = coalesce(excluded.password_hash, app_users.password_hash),
                  role = excluded.role,
                  active = excluded.active,
                  updated_at = now(),
                  deleted_at = null
                """,
                (
                    item.local_id,
                    item.name.strip(),
                    item.email.strip(),
                    item.password_hash or (_hash_password(item.password) if item.password else None),
                    item.role,
                    item.active,
                ),
            )
    except psycopg.Error as error:
        raise HTTPException(status_code=400, detail=f"Erro ao sincronizar usuario: {error}") from error
    return {"ok": True, "count": len(items)}


@app.get("/sync/users", dependencies=[Depends(require_token)])
def list_users():
    return _list_app_users(include_password_hash=True)


@app.get("/products", dependencies=[Depends(require_token)])
def products(updated_after: str | None = None):
    if updated_after:
        return fetch_all(
            "select * from products where updated_at > %s order by updated_at asc",
            (updated_after,),
        )
    return fetch_all("select * from products where deleted_at is null order by description asc")


@app.delete("/customers/{customer_id}", dependencies=[Depends(require_token)])
def delete_customer(customer_id: str, local_id: int | None = None, document: str | None = None, name: str | None = None, cleanup_duplicates: bool = False) -> dict[str, Any]:
    return _delete_customer_by_identifier(customer_id, local_id, document, name, cleanup_duplicates)


@app.delete("/products/{product_id}", dependencies=[Depends(require_token)])
def delete_product(product_id: str) -> dict[str, Any]:
    row_count = execute("update products set deleted_at = now(), active = false, updated_at = now() where id = %s and deleted_at is null", (product_id,))
    if row_count == 0:
        raise HTTPException(status_code=404, detail="Produto nao encontrado.")
    return {"ok": True, "id": product_id}


@app.post("/sync/products", dependencies=[Depends(require_token)])
def sync_products(items: list[ProductIn]) -> dict[str, Any]:
    try:
        for item in items:
            execute(
                """
                insert into products (
                  local_id, code, description, category, unit, price, cost, stock_quantity,
                  ncm, cfop, cest, origin, cst_csosn, icms_rate, pis_rate, cofins_rate,
                  active, updated_at
                )
                values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now())
                on conflict (code) do update set
                  local_id = excluded.local_id,
                  description = excluded.description,
                  category = excluded.category,
                  unit = excluded.unit,
                  price = excluded.price,
                  cost = excluded.cost,
                  stock_quantity = excluded.stock_quantity,
                  ncm = excluded.ncm,
                  cfop = excluded.cfop,
                  cest = excluded.cest,
                  origin = excluded.origin,
                  cst_csosn = excluded.cst_csosn,
                  icms_rate = excluded.icms_rate,
                  pis_rate = excluded.pis_rate,
                  cofins_rate = excluded.cofins_rate,
                  active = excluded.active,
                  updated_at = now()
                """,
                (
                    item.local_id,
                    item.code.strip(),
                    item.description.strip(),
                    _blank_to_none(item.category),
                    item.unit.strip() or "UN",
                    item.price,
                    item.cost,
                    item.stock_quantity,
                    _blank_to_none(item.ncm),
                    _blank_to_none(item.cfop),
                    _blank_to_none(item.cest),
                    item.origin or "0",
                    _blank_to_none(item.cst_csosn),
                    item.icms_rate,
                    item.pis_rate,
                    item.cofins_rate,
                    item.active,
                ),
            )
    except psycopg.Error as error:
        raise HTTPException(status_code=400, detail=f"Erro ao sincronizar produto: {error}") from error
    return {"ok": True, "count": len(items)}


@app.get("/orders", dependencies=[Depends(require_token)])
def orders(updated_after: str | None = None):
    if updated_after:
        return fetch_all(
            "select * from sales_orders where updated_at > %s order by updated_at asc",
            (updated_after,),
        )
    return fetch_all("select * from sales_orders where deleted_at is null order by created_at desc")


@app.get("/orders/full", dependencies=[Depends(require_token)])
def full_orders(updated_after: str | None = None) -> list[dict[str, Any]]:
    if updated_after:
        orders_rows = fetch_all(
            """
            select orders.*, customers.document as customer_document, users.email as seller_email
            from sales_orders orders
            left join customers on customers.id = orders.customer_id
            left join app_users users on users.id = orders.seller_id
            where orders.updated_at > %s and orders.deleted_at is null
            order by orders.created_at desc
            """,
            (updated_after,),
        )
    else:
        orders_rows = fetch_all(
            """
            select orders.*, customers.document as customer_document, users.email as seller_email
            from sales_orders orders
            left join customers on customers.id = orders.customer_id
            left join app_users users on users.id = orders.seller_id
            where orders.deleted_at is null
            order by orders.created_at desc
            """
        )
    result = []
    for order in orders_rows:
        items = fetch_all(
            "select * from sales_order_items where order_id = %s and deleted_at is null order by created_at asc",
            (order["id"],),
        )
        result.append({**order, "items": items})
    return result


@app.get("/orders/deleted", dependencies=[Depends(require_token)])
def deleted_orders() -> list[dict[str, Any]]:
    return fetch_all(
        """
        select id, number, updated_at, deleted_at
        from sales_orders
        where deleted_at is not null
        order by updated_at desc
        """
    )


@app.post("/orders", dependencies=[Depends(require_token)])
def create_order(order: OrderIn) -> dict[str, Any]:
    try:
        return _save_order(order)
    except psycopg.Error as error:
        raise HTTPException(status_code=400, detail=f"Erro ao salvar pedido: {error}") from error


def _save_order(order: OrderIn) -> dict[str, Any]:
    if not order.items:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Pedido sem produtos.")

    number = order.number or _next_order_number()
    customer = _find_customer(order.customer_id, order.customer_local_id, order.customer_document)
    seller = _find_seller(order.seller_id, order.seller_local_id, order.seller_email)
    existing = fetch_one("select id from sales_orders where number = %s and deleted_at is null limit 1", (number,))
    old_order = fetch_one("select status from sales_orders where id = %s limit 1", (existing["id"],)) if existing else None
    old_items = fetch_all("select product_id, quantity from sales_order_items where order_id = %s and deleted_at is null", (existing["id"],)) if existing else []
    customer_id = customer["id"] if customer else _uuid_or_none(order.customer_id)
    seller_id = seller["id"] if seller else _uuid_or_none(order.seller_id)
    values = (
        order.local_id,
        customer_id,
        order.customer_local_id,
        customer["name"] if customer else order.customer_name,
        seller_id,
        order.seller_local_id,
        seller["name"] if seller else order.seller_name,
        order.discount_type,
        order.discount,
        order.payment_type,
        order.cash_payment_method,
        order.credit_card_installments,
        order.credit_card_fee_percent,
        order.boleto_terms,
        order.extinguisher_validity,
        order.subtotal,
        order.total,
        order.notes,
        order.status,
    )
    if existing:
        order_id = existing["id"]
        if old_order and old_order["status"] == "finished":
            for old_item in old_items:
                if old_item["product_id"]:
                    execute(
                        "update products set stock_quantity = stock_quantity + %s, updated_at = now() where id = %s",
                        (old_item["quantity"], old_item["product_id"]),
                    )
        execute(
            """
            update sales_orders set
              local_id=%s, customer_id=%s, customer_local_id=%s, customer_name=%s,
              seller_id=%s, seller_local_id=%s, seller_name=%s, discount_type=%s,
              discount=%s, payment_type=%s, cash_payment_method=%s, credit_card_installments=%s,
              credit_card_fee_percent=%s, boleto_terms=%s,
              extinguisher_validity=%s, subtotal=%s, total=%s, notes=%s, status=%s,
              updated_at=now()
            where id=%s
            """,
            (*values, order_id),
        )
        execute("delete from sales_order_items where order_id = %s", (order_id,))
    else:
        order_id = fetch_one(
            """
            insert into sales_orders (
              local_id, number, customer_id, customer_local_id, customer_name,
              seller_id, seller_local_id, seller_name, discount_type, discount,
              payment_type, cash_payment_method, credit_card_installments, credit_card_fee_percent,
              boleto_terms, extinguisher_validity,
              subtotal, total, notes, status, updated_at
            )
            values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now())
            returning id
            """,
            (order.local_id, number, *values[1:]),
        )["id"]

    for item in order.items:
        product = _find_product(item.product_id, item.product_local_id, item.code)
        product_id = product["id"] if product else _uuid_or_none(item.product_id)
        execute(
            """
            insert into sales_order_items (
              local_id, order_id, product_id, product_local_id, code, description,
              unit, quantity, unit_price, total, updated_at
            )
            values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now())
            """,
            (
                item.local_id,
                order_id,
                product_id,
                item.product_local_id,
                item.code,
                item.description,
                item.unit,
                item.quantity,
                item.unit_price,
                round(item.quantity * item.unit_price, 2),
            ),
        )
        if order.status == "finished" and product_id:
            execute(
                "update products set stock_quantity = greatest(0, stock_quantity - %s), updated_at = now() where id = %s",
                (item.quantity, product_id),
            )
    return {"ok": True, "id": order_id, "number": number}


@app.get("/orders/{order_id}/items", dependencies=[Depends(require_token)])
def order_items(order_id: str):
    return fetch_all(
        "select * from sales_order_items where order_id = %s and deleted_at is null order by created_at asc",
        (order_id,),
    )


@app.delete("/orders/number/{number}", dependencies=[Depends(require_token)])
def delete_order_by_number(number: int) -> dict[str, Any]:
    order = fetch_one("select id, status from sales_orders where number = %s and deleted_at is null limit 1", (number,))
    if not order:
        raise HTTPException(status_code=404, detail="Pedido nao encontrado.")
    _restore_order_stock(order)
    execute("update sales_orders set deleted_at = now(), updated_at = now(), status = 'cancelled' where id = %s", (order["id"],))
    execute("update sales_order_items set deleted_at = now(), updated_at = now() where order_id = %s", (order["id"],))
    return {"ok": True, "number": number}


@app.delete("/orders/id/{order_id}", dependencies=[Depends(require_token)])
def delete_order_by_id(order_id: str) -> dict[str, Any]:
    order = fetch_one("select id, number, status from sales_orders where id = %s and deleted_at is null limit 1", (order_id,))
    if not order:
        raise HTTPException(status_code=404, detail="Pedido nao encontrado.")
    _restore_order_stock(order)
    execute("update sales_orders set deleted_at = now(), updated_at = now(), status = 'cancelled' where id = %s", (order_id,))
    execute("update sales_order_items set deleted_at = now(), updated_at = now() where order_id = %s", (order_id,))
    return {"ok": True, "id": order_id, "number": order["number"]}


def _restore_order_stock(order: dict[str, Any]) -> None:
    if order.get("status") != "finished":
        return
    items = fetch_all("select product_id, quantity from sales_order_items where order_id = %s and deleted_at is null", (order["id"],))
    for item in items:
        if item["product_id"]:
            execute(
                "update products set stock_quantity = stock_quantity + %s, updated_at = now() where id = %s",
                (item["quantity"], item["product_id"]),
            )


@app.get("/billing", dependencies=[Depends(require_token)])
def billing(status: str | None = None):
    if status:
        rows = fetch_all(
            "select * from billing_invoices where status = %s and deleted_at is null order by due_date asc",
            (status,),
        )
    else:
        rows = fetch_all("select * from billing_invoices where deleted_at is null order by due_date asc")
    return _refresh_existing_billings(rows)


@app.post("/sync/billing", dependencies=[Depends(require_token)])
def sync_billing(items: list[BillingIn]) -> dict[str, Any]:
    for item in items:
        _save_billing_item(item)
    return {"ok": True, "count": len(items)}


@app.post("/billing/{billing_id}/cancel", dependencies=[Depends(require_token)])
def cancel_billing_legacy(billing_id: str, payload: BillingCancelIn | None = None) -> dict[str, Any]:
    return _cancel_billing(billing_id, None, payload.reason if payload else None)


@app.delete("/billing/{billing_id}", dependencies=[Depends(require_token)])
def delete_billing_legacy(billing_id: str) -> dict[str, Any]:
    return _delete_billing(billing_id)


def _save_billing_item(item: BillingIn) -> dict[str, Any]:
    existing_order = None
    if item.order_id:
        existing_order = fetch_one("select id from sales_orders where id = %s and deleted_at is null", (item.order_id,))
    if existing_order is None and item.order_number:
        existing_order = fetch_one("select id from sales_orders where number = %s and deleted_at is null", (item.order_number,))
    order_id = existing_order["id"] if existing_order else _uuid_or_none(item.order_id)
    existing = None
    if item.cora_id:
        existing = fetch_one("select id from billing_invoices where cora_id = %s limit 1", (item.cora_id,))
    if existing is None:
        existing = fetch_one(
            """
            select id from billing_invoices
            where order_number = %s and cora_code = %s
            limit 1
            """,
            (item.order_number, item.cora_code),
        )
    row = fetch_one(
        """
        insert into billing_invoices (
          id, local_id, order_id, order_local_id, order_number, customer_id, customer_local_id,
          customer_name, amount, due_date, status, cora_id, cora_code, bank_slip_url,
          digitable_line, barcode, pix_copy_paste, issued_by_name, issued_at,
          cancelled_by_name, cancelled_at, cancellation_reason, updated_at, deleted_at
        )
        values (
          coalesce(%s::uuid, gen_random_uuid()), %s, %s, %s, %s, %s, %s,
          %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, coalesce(%s::timestamptz, now()),
          %s, %s, %s, now(), null
        )
        on conflict (id) do update set
          local_id = excluded.local_id,
          order_id = coalesce(excluded.order_id, billing_invoices.order_id),
          order_local_id = excluded.order_local_id,
          order_number = excluded.order_number,
          customer_id = coalesce(excluded.customer_id, billing_invoices.customer_id),
          customer_local_id = excluded.customer_local_id,
          customer_name = excluded.customer_name,
          amount = excluded.amount,
          due_date = excluded.due_date,
          status = excluded.status,
          cora_id = coalesce(excluded.cora_id, billing_invoices.cora_id),
          cora_code = coalesce(excluded.cora_code, billing_invoices.cora_code),
          bank_slip_url = coalesce(excluded.bank_slip_url, billing_invoices.bank_slip_url),
          digitable_line = coalesce(excluded.digitable_line, billing_invoices.digitable_line),
          barcode = coalesce(excluded.barcode, billing_invoices.barcode),
          pix_copy_paste = coalesce(excluded.pix_copy_paste, billing_invoices.pix_copy_paste),
          issued_by_name = coalesce(excluded.issued_by_name, billing_invoices.issued_by_name),
          issued_at = coalesce(excluded.issued_at, billing_invoices.issued_at),
          cancelled_by_name = coalesce(excluded.cancelled_by_name, billing_invoices.cancelled_by_name),
          cancelled_at = coalesce(excluded.cancelled_at, billing_invoices.cancelled_at),
          cancellation_reason = coalesce(excluded.cancellation_reason, billing_invoices.cancellation_reason),
          updated_at = now(),
          deleted_at = null
        returning *
        """,
        (
            existing["id"] if existing else None,
            item.local_id,
            order_id,
            item.order_local_id,
            item.order_number,
            _uuid_or_none(item.customer_id),
            item.customer_local_id,
            item.customer_name,
            item.amount,
            item.due_date,
            item.status,
            item.cora_id,
            item.cora_code,
            item.bank_slip_url,
            item.digitable_line,
            item.barcode,
            item.pix_copy_paste,
            item.issued_by_name,
            item.issued_at,
            item.cancelled_by_name,
            item.cancelled_at,
            item.cancellation_reason,
        ),
    )
    return row


def require_seller_session(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sessao mobile ausente.")
    token = authorization.removeprefix("Bearer ").strip()
    token_hash = _hash_session_token(token)
    user = fetch_one(
        """
        select users.id, users.local_id, users.name, users.email, users.role, users.active
        from mobile_sessions sessions
        join app_users users on users.id = sessions.user_id
        where sessions.token_hash = %s
          and sessions.revoked_at is null
          and sessions.expires_at > now()
          and users.active = true
          and users.deleted_at is null
        limit 1
        """,
        (token_hash,),
    )
    if user:
        return user
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sessao mobile invalida.")


@app.get("/mobile/bootstrap")
def mobile_bootstrap(user: dict[str, Any] = Depends(require_seller_session)) -> dict[str, Any]:
    return {
        "user": user,
        "customers": _customers_without_duplicates(active_only=True),
        "products": fetch_all("select * from products where active = true and deleted_at is null order by description asc"),
    }


@app.post("/mobile/customers")
def create_mobile_customer(customer: CustomerIn, user: dict[str, Any] = Depends(require_seller_session)) -> dict[str, Any]:
    try:
        row = _save_customer(customer)
    except psycopg.Error as error:
        raise HTTPException(status_code=400, detail=f"Erro ao cadastrar cliente: {error}") from error
    return {"ok": True, "id": row["id"]}


@app.post("/mobile/products")
def create_mobile_product(product: ProductIn, user: dict[str, Any] = Depends(require_seller_session)) -> dict[str, Any]:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Apenas administrador pode cadastrar produtos.")
    result = sync_products([product])
    return {"ok": True, "count": result["count"]}


@app.delete("/mobile/customers/{customer_id}")
def delete_mobile_customer(customer_id: str, local_id: int | None = None, document: str | None = None, name: str | None = None, cleanup_duplicates: bool = True, user: dict[str, Any] = Depends(require_seller_session)) -> dict[str, Any]:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Apenas administrador pode excluir clientes.")
    return _delete_customer_by_identifier(customer_id, local_id, document, name, cleanup_duplicates)


@app.delete("/mobile/products/{product_id}")
def delete_mobile_product(product_id: str, user: dict[str, Any] = Depends(require_seller_session)) -> dict[str, Any]:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Apenas administrador pode excluir produtos.")
    row_count = execute("update products set deleted_at = now(), active = false, updated_at = now() where id = %s and deleted_at is null", (product_id,))
    if row_count == 0:
        raise HTTPException(status_code=404, detail="Produto nao encontrado.")
    return {"ok": True, "id": product_id}


@app.get("/mobile/users")
def mobile_users(user: dict[str, Any] = Depends(require_seller_session)) -> list[dict[str, Any]]:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Apenas administrador pode listar usuarios.")
    return _list_app_users(include_password_hash=False)


@app.post("/mobile/users")
def save_mobile_user(payload: UserIn, user: dict[str, Any] = Depends(require_seller_session)) -> dict[str, Any]:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Apenas administrador pode salvar usuarios.")
    password_hash = payload.password_hash or (_hash_password(payload.password) if payload.password else None)
    if not password_hash:
        existing = fetch_one("select password_hash from app_users where lower(email) = lower(%s) and deleted_at is null", (payload.email.strip(),))
        if not existing:
            raise HTTPException(status_code=400, detail="Informe a senha do usuario.")
        password_hash = existing["password_hash"]
    row = fetch_one(
        """
        insert into app_users (local_id, name, email, password_hash, role, active, updated_at)
        values (%s,%s,lower(%s),%s,%s,%s,now())
        on conflict (email) do update set
          local_id = coalesce(excluded.local_id, app_users.local_id),
          name = excluded.name,
          password_hash = excluded.password_hash,
          role = excluded.role,
          active = excluded.active,
          updated_at = now(),
          deleted_at = null
        returning id
        """,
        (payload.local_id, payload.name.strip(), payload.email.strip(), password_hash, payload.role, payload.active),
    )
    return {"ok": True, "id": row["id"]}


@app.post("/mobile/users/{user_id}/active")
def set_mobile_user_active(user_id: str, payload: dict[str, bool], user: dict[str, Any] = Depends(require_seller_session)) -> dict[str, Any]:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Apenas administrador pode bloquear usuarios.")
    active = bool(payload.get("active", True))
    row_count = execute("update app_users set active = %s, updated_at = now() where id = %s and deleted_at is null", (active, user_id))
    if row_count == 0:
        raise HTTPException(status_code=404, detail="Usuario nao encontrado.")
    if not active:
        execute("update mobile_sessions set revoked_at = now() where user_id = %s and revoked_at is null", (user_id,))
    return {"ok": True, "id": user_id, "active": active}


@app.delete("/mobile/users/{user_id}")
def delete_mobile_user(user_id: str, user: dict[str, Any] = Depends(require_seller_session)) -> dict[str, Any]:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Apenas administrador pode excluir usuarios.")
    if str(user["id"]) == user_id:
        raise HTTPException(status_code=400, detail="Nao exclua o usuario que esta logado.")
    row_count = execute("update app_users set deleted_at = now(), active = false, updated_at = now() where id = %s and deleted_at is null", (user_id,))
    if row_count == 0:
        raise HTTPException(status_code=404, detail="Usuario nao encontrado.")
    execute("update mobile_sessions set revoked_at = now() where user_id = %s and revoked_at is null", (user_id,))
    return {"ok": True, "id": user_id}


@app.post("/mobile/orders")
def create_mobile_order(order: OrderIn, user: dict[str, Any] = Depends(require_seller_session)) -> dict[str, Any]:
    seller_update = {
        "seller_id": str(user["id"]),
        "seller_local_id": user["local_id"],
        "seller_email": user["email"],
        "seller_name": user["name"],
    }
    if user["role"] == "admin" and order.number is not None:
        existing = fetch_one(
            """
            select seller_id, seller_local_id, seller_name, users.email as seller_email
            from sales_orders orders
            left join app_users users on users.id = orders.seller_id
            where orders.number = %s and orders.deleted_at is null
            limit 1
            """,
            (order.number,),
        )
        if existing:
            seller_update = {
                "seller_id": str(existing["seller_id"]) if existing["seller_id"] else None,
                "seller_local_id": existing["seller_local_id"],
                "seller_email": existing["seller_email"],
                "seller_name": existing["seller_name"],
            }
    seller_order = order.model_copy(
        update=seller_update,
    )
    return create_order(seller_order)


@app.get("/mobile/orders")
def mobile_orders(user: dict[str, Any] = Depends(require_seller_session)) -> list[dict[str, Any]]:
    seller_filter = "" if user["role"] == "admin" else "where orders.seller_id = %s and orders.deleted_at is null"
    params = () if user["role"] == "admin" else (user["id"],)
    rows = fetch_all(
        f"""
        select orders.*, customers.document as customer_document, users.email as seller_email
        from sales_orders orders
        left join customers on customers.id = orders.customer_id
        left join app_users users on users.id = orders.seller_id
        {seller_filter if seller_filter else "where orders.deleted_at is null"}
        order by orders.created_at desc
        """,
        params,
    )
    result = []
    for order in rows:
        items = fetch_all(
            "select * from sales_order_items where order_id = %s and deleted_at is null order by created_at asc",
            (order["id"],),
        )
        result.append({**order, "items": items})
    return result


@app.get("/mobile/billing")
def mobile_billing(user: dict[str, Any] = Depends(require_seller_session)) -> list[dict[str, Any]]:
    if user["role"] == "admin":
        rows = fetch_all(
            """
            select billing.*
            from billing_invoices billing
            where billing.deleted_at is null
            order by billing.due_date asc
            """
        )
    else:
        rows = fetch_all(
            """
            select billing.*
            from billing_invoices billing
            left join sales_orders orders on orders.id = billing.order_id
            where orders.seller_id = %s and billing.deleted_at is null
            order by billing.due_date asc
            """,
            (user["id"],),
        )
    return _refresh_existing_billings(rows)


@app.post("/mobile/billing/{billing_id}/cancel")
def cancel_mobile_billing(billing_id: str, payload: BillingCancelIn | None = None, user: dict[str, Any] = Depends(require_seller_session)) -> dict[str, Any]:
    return _cancel_billing(billing_id, user, payload.reason if payload else None)


@app.delete("/mobile/billing/{billing_id}")
def delete_mobile_billing(billing_id: str, user: dict[str, Any] = Depends(require_seller_session)) -> dict[str, Any]:
    billing = _billing_for_user(billing_id, user)
    return _delete_billing(str(billing["id"]))


@app.post("/mobile/orders/{number}/billing")
def issue_mobile_billing(number: int, user: dict[str, Any] = Depends(require_seller_session)) -> dict[str, Any]:
    try:
        return _issue_mobile_billing(number, user)
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(status_code=400, detail=f"Falha ao emitir boleto: {type(error).__name__}: {error}") from error


def _issue_mobile_billing(number: int, user: dict[str, Any]) -> dict[str, Any]:
    order = _mobile_order_by_number(number, user)
    if order["total"] is None or float(order["total"]) <= 0:
        raise HTTPException(status_code=400, detail="Pedido sem valor para emitir boleto.")
    existing = fetch_all(
        """
        select *
        from billing_invoices
        where order_id = %s and deleted_at is null
        order by due_date asc
        """,
        (order["id"],),
    )
    if existing:
        refreshed = _refresh_existing_billings(existing)
        if all((item.get("bank_slip_url") or "").strip() for item in refreshed):
            return {"ok": True, "message": "Boleto oficial encontrado.", "items": refreshed}
        if _cora_configured() and any(not (item.get("cora_id") or "").strip() for item in refreshed):
            execute("update billing_invoices set deleted_at = now(), updated_at = now() where order_id = %s and deleted_at is null", (order["id"],))
        else:
            return {
                "ok": True,
                "message": "Boleto registrado, mas a Cora ainda nao retornou o PDF oficial. Tente novamente em instantes.",
                "items": refreshed,
            }

    terms = _boleto_days(order["boleto_terms"])
    amount = round(float(order["total"]) / len(terms), 2)
    created = []
    cora_ready = _cora_configured()
    if not cora_ready:
        raise HTTPException(status_code=400, detail="Cora nao configurada no Render. Configure CORA_ENABLED=true, CORA_CLIENT_ID, CORA_CERTIFICATE_PEM e CORA_PRIVATE_KEY_PEM.")
    for index, days in enumerate(terms):
        due_date = fetch_one("select (current_date + (%s::int * interval '1 day'))::date as due_date", (days,))["due_date"]
        item_amount = round(float(order["total"]) - amount * (len(terms) - 1), 2) if index == len(terms) - 1 else amount
        try:
            cora_data = _issue_cora_invoice(order, item_amount, str(due_date), days) if cora_ready else {}
        except HTTPException:
            raise
        except Exception as error:
            raise HTTPException(status_code=400, detail=f"Falha ao emitir boleto Cora: {type(error).__name__}: {error}") from error
        row = fetch_one(
            """
            insert into billing_invoices (
              order_id, order_number, customer_id, customer_local_id, customer_name,
              amount, due_date, status, cora_id, cora_code, bank_slip_url,
              digitable_line, barcode, pix_copy_paste, issued_by_id, issued_by_name,
              issued_at, updated_at
            )
            values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now(),now())
            returning *
            """,
            (
                order["id"],
                order["number"],
                order["customer_id"],
                order["customer_local_id"],
                order["customer_name"],
                item_amount,
                due_date,
                _billing_status(cora_data.get("status")) if cora_ready else "pending",
                cora_data.get("id"),
                cora_data.get("code") or f"PED-{order['number']}-{days}D",
                cora_data.get("bank_slip_url"),
                cora_data.get("digitable_line"),
                cora_data.get("barcode"),
                cora_data.get("pix_copy_paste"),
                user["id"],
                user["name"],
            ),
        )
        created.append(row)
    message = "Boleto emitido pela Cora."
    return {
        "ok": True,
        "message": message,
        "items": created,
    }


@app.get("/mobile/cora/status")
def mobile_cora_status(user: dict[str, Any] = Depends(require_seller_session)) -> dict[str, Any]:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Apenas administrador pode testar a Cora.")
    status_data = {
        "enabled": settings.cora_enabled,
        "production": settings.cora_production,
        "client_id": bool(settings.cora_client_id.strip()),
        "certificate": bool(_cora_cert_path() or settings.cora_certificate_pem.strip() or settings.cora_certificate_base64.strip()),
        "private_key": bool(_cora_key_path() or settings.cora_private_key_pem.strip() or settings.cora_private_key_base64.strip()),
        "certificate_base64": bool(settings.cora_certificate_base64.strip()),
        "private_key_base64": bool(settings.cora_private_key_base64.strip()),
        "ready": _cora_configured(),
    }
    if not status_data["ready"]:
        return {"ok": False, "detail": "Cora incompleta no Render.", **status_data}
    try:
        _cora_token()
    except HTTPException as error:
        return {"ok": False, "detail": error.detail, **status_data}
    except Exception as error:
        return {"ok": False, "detail": f"{type(error).__name__}: {error}", **status_data}
    return {"ok": True, "detail": "Cora autenticada com sucesso.", **status_data}


@app.get("/mobile/fiscal")
def mobile_fiscal(user: dict[str, Any] = Depends(require_seller_session)) -> list[dict[str, Any]]:
    if user["role"] == "admin":
        return fetch_all("select * from fiscal_invoices where deleted_at is null order by created_at desc")
    return fetch_all(
        """
        select invoices.*
        from fiscal_invoices invoices
        join sales_orders orders on orders.id = invoices.order_id
        where orders.seller_id = %s and invoices.deleted_at is null
        order by invoices.created_at desc
        """,
        (user["id"],),
    )


@app.get("/mobile/fiscal/status")
def mobile_fiscal_status(user: dict[str, Any] = Depends(require_seller_session)) -> dict[str, Any]:
    return {"ok": True, **_nfe_config_status()}


@app.post("/mobile/orders/{number}/fiscal")
def issue_mobile_fiscal(number: int, payload: FiscalIssueIn | None = None, user: dict[str, Any] = Depends(require_seller_session)) -> dict[str, Any]:
    order = _mobile_order_by_number(number, user)
    existing = fetch_one(
        """
        select *
        from fiscal_invoices
        where order_id = %s and status <> 'cancelled' and deleted_at is null
        order by created_at desc
        limit 1
        """,
        (order["id"],),
    )
    if existing and existing["status"] not in ("blocked", "rejected"):
        return {"ok": True, "message": "Nota fiscal ja registrada para este pedido.", "invoice": existing}

    data = payload or FiscalIssueIn()
    missing = _validate_mobile_fiscal_order(order)
    fiscal_status = _nfe_config_status()
    if missing:
        raise HTTPException(status_code=400, detail="Antes de emitir a nota no app, corrija:\n- " + "\n- ".join(missing))

    series = data.series or settings.nfe_series or 1
    environment = "producao" if settings.nfe_production else "homologacao"
    next_number = int(existing["number"]) if existing else _next_fiscal_number(series)
    if not fiscal_status["ready"]:
        status_text = "blocked"
        message = "Nota validada, mas a emissao online pelo Render ainda nao esta configurada: " + "; ".join(fiscal_status["missing"])
    else:
        status_text = "blocked"
        message = (
            "Nota validada e pronta para o motor fiscal online. "
            "Falta ativar o assinador/envio SEFAZ no backend para autorizar e gerar DANFE oficial."
        )

    if existing:
        row = fetch_one(
            """
            update fiscal_invoices set
              series=%s, number=%s, environment=%s, status=%s, message=%s,
              issued_by_id=%s, issued_by_name=%s, issued_at=coalesce(issued_at, now()),
              updated_at=now()
            where id=%s
            returning *
            """,
            (series, next_number, environment, status_text, message, user["id"], user["name"], existing["id"]),
        )
        return {"ok": True, "message": message, "invoice": row, "fiscal_ready": fiscal_status["ready"]}

    row = fetch_one(
        """
        insert into fiscal_invoices (
          order_id, order_number, series, number, environment, status, message,
          issued_by_id, issued_by_name, issued_at, updated_at
        )
        values (%s,%s,%s,%s,%s,%s,%s,%s,%s,now(),now())
        returning *
        """,
        (
            order["id"],
            order["number"],
            series,
            next_number,
            environment,
            status_text,
            data.message or message,
            user["id"],
            user["name"],
        ),
    )
    return {"ok": True, "message": message, "invoice": row, "fiscal_ready": fiscal_status["ready"]}


@app.post("/mobile/fiscal/{invoice_id}/cancel")
def cancel_mobile_fiscal(invoice_id: str, payload: dict[str, str] | None = None, user: dict[str, Any] = Depends(require_seller_session)) -> dict[str, Any]:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Apenas administrador pode cancelar notas fiscais.")
    invoice_uuid = _uuid_or_none(invoice_id)
    if not invoice_uuid:
        raise HTTPException(status_code=404, detail="Nota fiscal nao encontrada.")
    invoice = fetch_one("select * from fiscal_invoices where id = %s and deleted_at is null limit 1", (invoice_uuid,))
    if not invoice:
        raise HTTPException(status_code=404, detail="Nota fiscal nao encontrada.")
    if invoice["status"] != "authorized":
        raise HTTPException(status_code=400, detail="Apenas NF-e autorizada pode ser cancelada na SEFAZ.")
    raise HTTPException(
        status_code=400,
        detail="Cancelamento SEFAZ pelo app ainda depende do motor fiscal online no Render. Cancele pelo Windows enquanto essa etapa e finalizada.",
    )


@app.delete("/mobile/fiscal/{invoice_id}")
def delete_mobile_fiscal(invoice_id: str, user: dict[str, Any] = Depends(require_seller_session)) -> dict[str, Any]:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Apenas administrador pode excluir notas fiscais.")
    invoice_uuid = _uuid_or_none(invoice_id)
    if not invoice_uuid:
        raise HTTPException(status_code=404, detail="Nota fiscal nao encontrada.")
    row_count = execute("update fiscal_invoices set deleted_at = now(), updated_at = now() where id = %s and deleted_at is null", (invoice_uuid,))
    if row_count == 0:
        raise HTTPException(status_code=404, detail="Nota fiscal nao encontrada.")
    return {"ok": True, "id": invoice_uuid}


@app.delete("/mobile/orders/id/{order_id}")
def delete_mobile_order_by_id(order_id: str, user: dict[str, Any] = Depends(require_seller_session)) -> dict[str, Any]:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Apenas administrador pode excluir pedidos.")
    return delete_order_by_id(order_id)


@app.delete("/mobile/orders/{number}")
def delete_mobile_order(number: int, user: dict[str, Any] = Depends(require_seller_session)) -> dict[str, Any]:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Apenas administrador pode excluir pedidos.")
    return delete_order_by_number(number)


def _delete_customer_by_identifier(customer_id: str, local_id: int | None = None, document: str | None = None, name: str | None = None, cleanup_duplicates: bool = False) -> dict[str, Any]:
    customer = None
    customer_uuid = _uuid_or_none(customer_id)
    if customer_uuid:
        customer = fetch_one("select id from customers where id = %s and deleted_at is null limit 1", (customer_uuid,))
    if customer is None and local_id is not None:
        customer = fetch_one("select id from customers where local_id = %s and deleted_at is null limit 1", (local_id,))
    document_digits = _digits_only(document) or _digits_only(customer_id)
    if customer is None and document_digits:
        customer = fetch_one(
            "select id from customers where regexp_replace(coalesce(document, ''), '\\D', '', 'g') = %s and deleted_at is null limit 1",
            (document_digits,),
        )
    normalized_name = re.sub(r"\s+", " ", (name or "").strip().lower())
    if customer is None and normalized_name:
        customer = fetch_one(
            """
            select id
            from customers
            where regexp_replace(lower(trim(name)), '\\s+', ' ', 'g') = %s
              and deleted_at is null
            order by
              (regexp_replace(coalesce(document, ''), '\\D', '', 'g') <> '') asc,
              updated_at desc
            limit 1
            """,
            (normalized_name,),
        )
    if customer is None:
        raise HTTPException(status_code=404, detail="Cliente nao encontrado.")
    execute("update customers set deleted_at = now(), active = false, updated_at = now() where id = %s", (customer["id"],))
    if cleanup_duplicates and document_digits:
        execute(
            """
            update customers
            set deleted_at = now(), active = false, updated_at = now()
            where regexp_replace(coalesce(document, ''), '\\D', '', 'g') = %s
              and deleted_at is null
              and nullif(trim(coalesce(state_registration, '')), '') is null
            """,
            (document_digits,),
        )
    if cleanup_duplicates and normalized_name:
        execute(
            """
            update customers
            set deleted_at = now(), active = false, updated_at = now()
            where regexp_replace(lower(trim(name)), '\\s+', ' ', 'g') = %s
              and deleted_at is null
              and regexp_replace(coalesce(document, ''), '\\D', '', 'g') = ''
            """,
            (normalized_name,),
        )
    return {"ok": True, "id": customer["id"]}


def _save_customer(item: CustomerIn) -> dict[str, Any]:
    document = _digits_only(item.document)
    existing = None
    item_uuid = _uuid_or_none(item.id) if item.id else None
    if item_uuid:
        existing = fetch_one("select id from customers where id = %s and deleted_at is null limit 1", (item_uuid,))
    if existing is None and document:
        existing = fetch_one(
            "select id from customers where regexp_replace(coalesce(document, ''), '\\D', '', 'g') = %s and deleted_at is null limit 1",
            (document,),
        )
    if existing is None:
        existing = fetch_one(
            """
            select id
            from customers
            where lower(name) = lower(%s)
              and coalesce(phone, '') = coalesce(%s, '')
              and coalesce(email, '') = coalesce(%s, '')
              and deleted_at is null
            limit 1
            """,
            (item.name.strip(), _blank_to_none(item.phone), _blank_to_none(item.email)),
        )

    values = (
        item.local_id,
        item.name.strip(),
        _blank_to_none(item.trade_name),
        document or None,
        _blank_to_none(item.state_registration),
        _blank_to_none(item.address),
        _blank_to_none(item.phone),
        _blank_to_none(item.whatsapp),
        _blank_to_none(item.email),
        _blank_to_none(item.business_license_expiration),
        _blank_to_none(item.notes),
        item.active,
    )
    if existing:
        execute(
            """
            update customers set
              local_id = coalesce(%s, local_id),
              name = %s,
              trade_name = %s,
              document = coalesce(%s, document),
              state_registration = %s,
              address = %s,
              phone = %s,
              whatsapp = %s,
              email = %s,
              business_license_expiration = %s,
              notes = %s,
              active = %s,
              updated_at = now(),
              deleted_at = null
            where id = %s
            """,
            (*values, existing["id"]),
        )
        return {"id": existing["id"]}
    return fetch_one(
        """
        insert into customers (
          local_id, name, trade_name, document, state_registration, address,
          phone, whatsapp, email, business_license_expiration, notes, active, updated_at
        )
        values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now())
        returning id
        """,
        values,
    )


def _list_app_users(include_password_hash: bool = False) -> list[dict[str, Any]]:
    try:
        rows = fetch_all(
            """
            select id, local_id, name, email, password_hash, role, active
            from app_users
            where deleted_at is null
            order by name asc
            """
        )
    except psycopg.Error as error:
        raise HTTPException(status_code=400, detail=f"Erro ao listar usuarios: {error}") from error

    result = []
    for row in rows:
        email = str(row.get("email") or "")
        if email.startswith("vendedor.online") and email.endswith("@licensafe.local"):
            continue
        item = {
            "id": str(row.get("id") or ""),
            "local_id": row.get("local_id"),
            "name": str(row.get("name") or ""),
            "email": email,
            "role": str(row.get("role") or "seller"),
            "active": row.get("active") is not False,
        }
        if include_password_hash:
            item["password_hash"] = str(row.get("password_hash") or "")
        result.append(item)
    return result


def _customers_without_duplicates(active_only: bool = False) -> list[dict[str, Any]]:
    active_clause = "and active = true" if active_only else ""
    return fetch_all(
        f"""
        select * from (
          select distinct on (dedupe_key) *
          from (
            select customers.*,
              case
                when regexp_replace(coalesce(document, ''), '\\D', '', 'g') <> ''
                  then regexp_replace(coalesce(document, ''), '\\D', '', 'g')
                when lower(trim(coalesce(email, ''))) <> ''
                  then 'email:' || lower(trim(email))
                when regexp_replace(coalesce(phone, whatsapp, ''), '\\D', '', 'g') <> ''
                  then 'phone:' || regexp_replace(coalesce(phone, whatsapp, ''), '\\D', '', 'g')
                else 'name:' || regexp_replace(lower(trim(name)), '\\s+', ' ', 'g')
              end as dedupe_key
            from customers
            where deleted_at is null
              {active_clause}
          ) ranked
          order by dedupe_key,
            (nullif(trim(coalesce(state_registration, '')), '') is not null) desc,
            updated_at desc
        ) cleaned
        order by name asc
        """
    )


def _hash_password(password: str) -> str:
    return hashlib.sha256(f"licensafe:{password}".encode("utf-8")).hexdigest()


def _create_mobile_session(user_id: str) -> str:
    token = secrets.token_urlsafe(48)
    execute(
        """
        insert into mobile_sessions (user_id, token_hash, expires_at)
        values (%s, %s, now() + interval '30 days')
        """,
        (user_id, _hash_session_token(token)),
    )
    return token


def _hash_session_token(token: str) -> str:
    return hashlib.sha256(f"licensafe-mobile:{token}".encode("utf-8")).hexdigest()


def _next_order_number() -> int:
    row = fetch_one("select coalesce(max(number), 0) + 1 as number from sales_orders")
    return int(row["number"])


def _find_customer(customer_id: str | None, local_id: int | None, document: str | None):
    customer_uuid = _uuid_or_none(customer_id)
    if customer_uuid:
        return fetch_one("select * from customers where id = %s and deleted_at is null", (customer_uuid,))
    if local_id is not None:
        row = fetch_one("select * from customers where local_id = %s and deleted_at is null limit 1", (local_id,))
        if row:
            return row
    if document:
        return fetch_one("select * from customers where document = %s and deleted_at is null limit 1", (document,))
    return None


def _find_seller(seller_id: str | None, local_id: int | None, email: str | None):
    seller_uuid = _uuid_or_none(seller_id)
    if seller_uuid:
        return fetch_one("select * from app_users where id = %s and deleted_at is null", (seller_uuid,))
    if local_id is not None:
        row = fetch_one("select * from app_users where local_id = %s and deleted_at is null limit 1", (local_id,))
        if row:
            return row
    if email:
        return fetch_one("select * from app_users where lower(email) = lower(%s) and deleted_at is null limit 1", (email,))
    return None


def _find_product(product_id: str | None, local_id: int | None, code: str):
    product_uuid = _uuid_or_none(product_id)
    if product_uuid:
        return fetch_one("select * from products where id = %s and deleted_at is null", (product_uuid,))
    if local_id is not None:
        row = fetch_one("select * from products where local_id = %s and deleted_at is null limit 1", (local_id,))
        if row:
            return row
    return fetch_one("select * from products where code = %s and deleted_at is null limit 1", (code,))


def _mobile_order_by_number(number: int, user: dict[str, Any]) -> dict[str, Any]:
    order = fetch_one(
        "select * from sales_orders where number = %s and deleted_at is null limit 1",
        (number,),
    )
    if not order:
        raise HTTPException(status_code=404, detail="Pedido nao encontrado.")
    if user["role"] != "admin" and str(order["seller_id"] or "") != str(user["id"]):
        raise HTTPException(status_code=403, detail="Pedido pertence a outro vendedor.")
    return order


def _boleto_days(value: str | None) -> list[int]:
    days = []
    labels = {
        "days3": 3,
        "days5": 5,
        "days7": 7,
        "days15": 15,
        "days30": 30,
        "days60": 60,
        "days90": 90,
    }
    for item in (value or "").split(","):
        text = item.strip()
        if not text:
            continue
        if text in labels:
            days.append(labels[text])
            continue
        digits = _digits_only(text)
        if digits:
            days.append(int(digits))
    return sorted(set(days)) or [30]


def _next_fiscal_number(series: int) -> int:
    row = fetch_one(
        "select coalesce(max(number), 0) + 1 as number from fiscal_invoices where series = %s",
        (series,),
    )
    return int(row["number"])


def _nfe_config_status() -> dict[str, Any]:
    missing: list[str] = []
    if not settings.nfe_online_enabled:
        missing.append("NFE_ONLINE_ENABLED=true")
    if len(_digits_only(settings.nfe_issuer_cnpj)) != 14:
        missing.append("NFE_ISSUER_CNPJ com 14 digitos")
    if not settings.nfe_issuer_ie.strip():
        missing.append("NFE_ISSUER_IE")
    if not settings.nfe_issuer_uf.strip():
        missing.append("NFE_ISSUER_UF")
    if len(_digits_only(settings.nfe_city_code)) != 7:
        missing.append("NFE_CITY_CODE com 7 digitos")
    if not settings.nfe_tax_regime.strip():
        missing.append("NFE_TAX_REGIME")
    if settings.nfe_series <= 0:
        missing.append("NFE_SERIES")
    if not settings.nfe_certificate_pfx_base64.strip():
        missing.append("NFE_CERTIFICATE_PFX_BASE64")
    if not settings.nfe_certificate_password.strip():
        missing.append("NFE_CERTIFICATE_PASSWORD")
    return {
        "ready": not missing,
        "missing": missing,
        "environment": "producao" if settings.nfe_production else "homologacao",
        "series": settings.nfe_series,
        "issuer_uf": settings.nfe_issuer_uf,
    }


def _validate_mobile_fiscal_order(order: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    customer = fetch_one("select * from customers where id = %s and deleted_at is null", (order["customer_id"],)) if order.get("customer_id") else None
    if not customer:
        missing.append("cliente do pedido nao encontrado")
    else:
        document = _digits_only(customer.get("document"))
        if len(document) not in (11, 14):
            missing.append("cliente com CPF/CNPJ valido")
        if len(document) == 14 and not _digits_only(customer.get("state_registration")):
            missing.append("IE do cliente CNPJ")
        if not str(customer.get("name") or "").strip():
            missing.append("razao social/nome do cliente")
        if not str(customer.get("address") or "").strip():
            missing.append("endereco do cliente")

    if len(_digits_only(settings.nfe_issuer_cnpj)) != 14:
        missing.append("CNPJ da empresa no Render")
    if not settings.nfe_issuer_ie.strip():
        missing.append("IE da empresa no Render")
    if len(_digits_only(settings.nfe_city_code)) != 7:
        missing.append("codigo IBGE do municipio emissor no Render")

    items = fetch_all(
        """
        select items.description as item_description, products.ncm, products.cfop,
               products.cst_csosn, products.origin
        from sales_order_items items
        left join products on products.id = items.product_id
        where items.order_id = %s and items.deleted_at is null
        order by items.created_at asc
        """,
        (order["id"],),
    )
    if not items:
        missing.append("produtos do pedido")
    for item in items:
        label = str(item.get("item_description") or "Produto")
        if len(_digits_only(item.get("ncm"))) != 8:
            missing.append(f"{label}: NCM com 8 digitos")
        if len(_digits_only(item.get("cfop"))) != 4:
            missing.append(f"{label}: CFOP com 4 digitos")
        if not str(item.get("cst_csosn") or "").strip():
            missing.append(f"{label}: CST/CSOSN")
        if not str(item.get("origin") or "").strip():
            missing.append(f"{label}: origem")
    return missing


def _cora_configured() -> bool:
    return bool(
        settings.cora_enabled
        and settings.cora_client_id.strip()
        and (_cora_cert_path() or settings.cora_certificate_pem.strip() or settings.cora_certificate_base64.strip())
        and (_cora_key_path() or settings.cora_private_key_pem.strip() or settings.cora_private_key_base64.strip())
    )


def _issue_cora_invoice(order: dict[str, Any], amount: float, due_date: str, days: int) -> dict[str, Any]:
    customer = fetch_one("select * from customers where id = %s and deleted_at is null", (order["customer_id"],)) if order["customer_id"] else None
    if not customer:
        raise HTTPException(status_code=400, detail="Cliente do pedido nao encontrado para emitir boleto.")
    document = _digits_only(customer["document"])
    if len(document) not in (11, 14):
        raise HTTPException(status_code=400, detail="Cadastre CPF ou CNPJ valido no cliente antes de emitir boleto.")

    token = _cora_token()
    body = {
        "code": f"PED-{order['number']}-{days}D",
        "customer": {
            "name": customer["name"],
            **({"email": customer["email"].strip()} if customer.get("email") else {}),
            "document": {
                "identity": document,
                "type": "CPF" if len(document) == 11 else "CNPJ",
            },
        },
        "services": [
            {
                "name": f"Pedido {order['number']}",
                "description": f"Pedido Licensafe - {days} dias",
                "amount": int(round(amount * 100)),
            }
        ],
        "payment_terms": {"due_date": due_date},
        "payment_forms": ["BANK_SLIP"],
    }
    try:
        response = requests.post(
            f"{_cora_api_base()}/v2/invoices/",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "accept": "application/json",
                "Idempotency-Key": str(uuid4()),
            },
            json=body,
            cert=_cora_cert_tuple(),
            timeout=45,
        )
    except requests.RequestException as error:
        raise HTTPException(status_code=400, detail=f"Falha ao conectar na Cora: {error}") from error
    if response.status_code < 200 or response.status_code >= 300:
        raise HTTPException(status_code=400, detail=_cora_error("Falha ao emitir boleto Cora", response))
    data = response.json()
    parsed = _parse_cora_invoice_data(data)
    if not parsed.get("bank_slip_url") and parsed.get("id") and _billing_status(parsed.get("status")) == "open":
        parsed = {**parsed, **_activate_cora_invoice(str(parsed["id"]), token)}
    return parsed


def _parse_cora_invoice_data(data: dict[str, Any]) -> dict[str, Any]:
    payment_options = data.get("payment_options") or data.get("paymentOptions") or {}
    bank_slip = payment_options.get("bank_slip") or payment_options.get("bankSlip") or data.get("bank_slip") or data.get("bankSlip") or {}
    pix = payment_options.get("pix") or data.get("pix") or {}
    return {
        "id": data.get("id"),
        "code": data.get("code"),
        "status": data.get("status"),
        "bank_slip_url": bank_slip.get("url")
        or data.get("document_url")
        or data.get("documentUrl")
        or _find_first_string(data, ["bank_slip_url", "bank_slip_pdf_url", "document_url", "documentUrl"]),
        "digitable_line": bank_slip.get("digitable")
        or bank_slip.get("digitable_line")
        or bank_slip.get("digitableLine")
        or _find_first_string(data, ["digitable", "digitable_line", "digitableLine", "linha_digitavel"]),
        "barcode": bank_slip.get("barcode"),
        "pix_copy_paste": pix.get("emv") or pix.get("copy_paste"),
    }


def _refresh_existing_billings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not _cora_configured():
        return items
    refreshed = []
    token: str | None = None
    for item in items:
        if not (item.get("cora_id") or "").strip():
            refreshed.append(item)
            continue
        token = token or _cora_token()
        try:
            cora_data = _get_cora_invoice(str(item["cora_id"]), token)
        except HTTPException as error:
            if "Status: 404" in str(error.detail):
                execute("update billing_invoices set deleted_at = now(), updated_at = now() where id = %s", (item["id"],))
                continue
            raise
        row = fetch_one(
            """
            update billing_invoices set
              status=%s, cora_code=%s, bank_slip_url=%s, digitable_line=%s,
              barcode=%s, pix_copy_paste=%s, updated_at=now()
            where id=%s
            returning *
            """,
            (
                _billing_status(cora_data.get("status")),
                cora_data.get("code") or item.get("cora_code"),
                cora_data.get("bank_slip_url") or item.get("bank_slip_url"),
                cora_data.get("digitable_line") or item.get("digitable_line"),
                cora_data.get("barcode") or item.get("barcode"),
                cora_data.get("pix_copy_paste") or item.get("pix_copy_paste"),
                item["id"],
            ),
        )
        refreshed.append(row)
    return refreshed


def _cancel_billing(billing_id: str, user: dict[str, Any] | None, reason: str | None) -> dict[str, Any]:
    billing = _billing_for_user(billing_id, user)
    if billing["status"] == "paid":
        raise HTTPException(status_code=400, detail="Boleto pago nao pode ser cancelado.")
    if billing.get("cora_id") and _cora_configured():
        _cancel_cora_invoice(str(billing["cora_id"]))
    cancelled_name = user["name"] if user else "Administrador Windows"
    cancelled_id = user["id"] if user else None
    row = fetch_one(
        """
        update billing_invoices set
          status = 'cancelled',
          cancelled_by_id = %s,
          cancelled_by_name = %s,
          cancelled_at = now(),
          cancellation_reason = %s,
          updated_at = now()
        where id = %s
        returning *
        """,
        (cancelled_id, cancelled_name, _blank_to_none(reason) or "Cancelado pelo Licensafe", billing["id"]),
    )
    return {"ok": True, "message": "Boleto cancelado.", "item": row}


def _billing_for_user(billing_id: str, user: dict[str, Any] | None) -> dict[str, Any]:
    billing = None
    billing_uuid = _uuid_or_none(billing_id)
    if billing_uuid:
        billing = fetch_one("select * from billing_invoices where id = %s and deleted_at is null limit 1", (billing_uuid,))
    if not billing:
        billing = fetch_one("select * from billing_invoices where cora_id = %s and deleted_at is null limit 1", (billing_id,))
    if not billing:
        raise HTTPException(status_code=404, detail="Boleto nao encontrado.")
    if user and user["role"] != "admin":
        owner = fetch_one(
            """
            select orders.seller_id
            from sales_orders orders
            where orders.id = %s and orders.deleted_at is null
            limit 1
            """,
            (billing["order_id"],),
        )
        if not owner or str(owner["seller_id"]) != str(user["id"]):
            raise HTTPException(status_code=403, detail="Boleto pertence a outro vendedor.")
    return billing


def _delete_billing(billing_id: str) -> dict[str, Any]:
    billing = None
    billing_uuid = _uuid_or_none(billing_id)
    if billing_uuid:
        billing = fetch_one("select id from billing_invoices where id = %s and deleted_at is null limit 1", (billing_uuid,))
    if not billing:
        billing = fetch_one("select id from billing_invoices where cora_id = %s and deleted_at is null limit 1", (billing_id,))
    if not billing:
        raise HTTPException(status_code=404, detail="Boleto nao encontrado.")
    execute("update billing_invoices set deleted_at = now(), updated_at = now() where id = %s", (billing["id"],))
    return {"ok": True, "id": billing["id"]}


def _get_cora_invoice(invoice_id: str, token: str) -> dict[str, Any]:
    try:
        response = requests.get(
            f"{_cora_api_base()}/v2/invoices/{invoice_id}",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", "accept": "application/json"},
            cert=_cora_cert_tuple(),
            timeout=30,
        )
    except requests.RequestException as error:
        raise HTTPException(status_code=400, detail=f"Falha ao consultar boleto na Cora: {error}") from error
    if response.status_code < 200 or response.status_code >= 300:
        raise HTTPException(status_code=400, detail=_cora_error("Falha ao consultar boleto Cora", response))
    data = response.json()
    parsed = _parse_cora_invoice_data(data)
    if not parsed.get("bank_slip_url") and parsed.get("id") and _billing_status(parsed.get("status")) == "open":
        parsed = {**parsed, **_activate_cora_invoice(str(parsed["id"]), token)}
    return parsed


def _activate_cora_invoice(invoice_id: str, token: str) -> dict[str, Any]:
    try:
        response = requests.post(
            f"{_cora_api_base()}/invoices/pay",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "accept": "application/json",
                "Idempotency-Key": str(uuid4()),
            },
            json={"id": invoice_id},
            cert=_cora_cert_tuple(),
            timeout=45,
        )
    except requests.RequestException as error:
        raise HTTPException(status_code=400, detail=f"Falha ao ativar boleto na Cora: {error}") from error
    if response.status_code < 200 or response.status_code >= 300:
        raise HTTPException(status_code=400, detail=_cora_error("Falha ao ativar boleto Cora", response))
    return _parse_cora_invoice_data(response.json())


def _cancel_cora_invoice(invoice_id: str) -> None:
    token = _cora_token()
    try:
        response = requests.delete(
            f"{_cora_api_base()}/v2/invoices/{invoice_id}",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "accept": "application/json",
                "Idempotency-Key": str(uuid4()),
            },
            cert=_cora_cert_tuple(),
            timeout=45,
        )
    except requests.RequestException as error:
        raise HTTPException(status_code=400, detail=f"Falha ao cancelar boleto na Cora: {error}") from error
    if response.status_code not in (200, 202, 204):
        raise HTTPException(status_code=400, detail=_cora_error("Falha ao cancelar boleto Cora", response))


def _cora_token() -> str:
    try:
        response = requests.post(
            f"{_cora_auth_base()}/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"grant_type": "client_credentials", "client_id": settings.cora_client_id.strip()},
            cert=_cora_cert_tuple(),
            timeout=30,
        )
    except requests.RequestException as error:
        raise HTTPException(status_code=400, detail=f"Falha ao autenticar na Cora: {error}") from error
    if response.status_code < 200 or response.status_code >= 300:
        raise HTTPException(status_code=400, detail=_cora_error("Falha ao autenticar na Cora", response))
    token = response.json().get("access_token")
    if not token:
        raise HTTPException(status_code=400, detail="A Cora nao retornou access_token.")
    return str(token)


def _cora_auth_base() -> str:
    return "https://matls-clients.api.cora.com.br" if settings.cora_production else "https://matls-clients.api.stage.cora.com.br"


def _cora_api_base() -> str:
    return "https://matls-clients.api.cora.com.br" if settings.cora_production else "https://matls-clients.api.stage.cora.com.br"


def _cora_cert_tuple() -> tuple[str, str]:
    cert_path = _cora_cert_path()
    key_path = _cora_key_path()
    if cert_path and key_path:
        return cert_path, key_path
    temp_dir = os.path.join(tempfile.gettempdir(), "licensafe_cora")
    os.makedirs(temp_dir, exist_ok=True)
    cert_path = os.path.join(temp_dir, "certificate.pem")
    key_path = os.path.join(temp_dir, "private-key.key")
    if settings.cora_certificate_base64.strip():
        with open(cert_path, "wb") as cert_file:
            cert_file.write(base64.b64decode(settings.cora_certificate_base64.strip()))
    else:
        with open(cert_path, "w", encoding="utf-8") as cert_file:
            cert_file.write(_pem_text(settings.cora_certificate_pem))
    if settings.cora_private_key_base64.strip():
        with open(key_path, "wb") as key_file:
            key_file.write(base64.b64decode(settings.cora_private_key_base64.strip()))
    else:
        with open(key_path, "w", encoding="utf-8") as key_file:
            key_file.write(_pem_text(settings.cora_private_key_pem))
    return cert_path, key_path


def _pem_text(value: str) -> str:
    return value.strip().strip('"').strip("'").replace("\\r\\n", "\n").replace("\\n", "\n") + "\n"


def _cora_cert_path() -> str | None:
    path = settings.cora_certificate_path.strip()
    return path if path and os.path.exists(path) else None


def _cora_key_path() -> str | None:
    path = settings.cora_private_key_path.strip()
    return path if path and os.path.exists(path) else None


def _billing_status(value: Any) -> str:
    text = str(value or "").lower()
    if text in ("paid", "closed", "received"):
        return "paid"
    if text in ("cancelled", "canceled"):
        return "cancelled"
    if text in ("overdue", "past_due"):
        return "overdue"
    return "open"


def _find_first_string(value: Any, keys: list[str]) -> str | None:
    if isinstance(value, dict):
        for key in keys:
            found = value.get(key)
            if isinstance(found, str) and found.strip():
                return found
        for item in value.values():
            found = _find_first_string(item, keys)
            if found:
                return found
    if isinstance(value, list):
        for item in value:
            found = _find_first_string(item, keys)
            if found:
                return found
    return None


def _cora_error(title: str, response: requests.Response) -> str:
    detail = response.text
    try:
        data = response.json()
        if isinstance(data, dict):
            parts = [
                str(data.get("message") or ""),
                str(data.get("error_description") or ""),
                str(data.get("error") or ""),
                str(data.get("detail") or ""),
                str(data.get("errors") or ""),
            ]
            detail = "\n".join(part for part in parts if part.strip()) or response.text
    except ValueError:
        pass
    return f"{title}\nStatus: {response.status_code}\nDetalhe: {detail}"


def _blank_to_none(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None


def _uuid_or_none(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(UUID(str(value)))
    except (TypeError, ValueError):
        return None


def _digits_only(value: str | None) -> str:
    return "".join(char for char in (value or "") if char.isdigit())
