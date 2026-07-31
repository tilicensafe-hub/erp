import hashlib
import secrets
from typing import Any
from uuid import UUID

import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel

from .db import execute, fetch_all, fetch_one
from .config import settings
from .security import require_token

API_VERSION = "1.0.14"

app = FastAPI(title="Licensafe API", version=API_VERSION)


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
def delete_customer(customer_id: str) -> dict[str, Any]:
    row_count = execute("update customers set deleted_at = now(), active = false, updated_at = now() where id = %s and deleted_at is null", (customer_id,))
    if row_count == 0:
        raise HTTPException(status_code=404, detail="Cliente nao encontrado.")
    return {"ok": True, "id": customer_id}


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
                  local_id, code, description, category, unit, price, cost,
                  ncm, cfop, cest, origin, cst_csosn, icms_rate, pis_rate, cofins_rate,
                  active, updated_at
                )
                values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now())
                on conflict (code) do update set
                  local_id = excluded.local_id,
                  description = excluded.description,
                  category = excluded.category,
                  unit = excluded.unit,
                  price = excluded.price,
                  cost = excluded.cost,
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
                product["id"] if product else _uuid_or_none(item.product_id),
                item.product_local_id,
                item.code,
                item.description,
                item.unit,
                item.quantity,
                item.unit_price,
                round(item.quantity * item.unit_price, 2),
            ),
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
    order = fetch_one("select id from sales_orders where number = %s and deleted_at is null limit 1", (number,))
    if not order:
        raise HTTPException(status_code=404, detail="Pedido nao encontrado.")
    execute("update sales_orders set deleted_at = now(), updated_at = now(), status = 'cancelled' where id = %s", (order["id"],))
    execute("update sales_order_items set deleted_at = now(), updated_at = now() where order_id = %s", (order["id"],))
    return {"ok": True, "number": number}


@app.delete("/orders/id/{order_id}", dependencies=[Depends(require_token)])
def delete_order_by_id(order_id: str) -> dict[str, Any]:
    order = fetch_one("select number from sales_orders where id = %s and deleted_at is null limit 1", (order_id,))
    if not order:
        raise HTTPException(status_code=404, detail="Pedido nao encontrado.")
    execute("update sales_orders set deleted_at = now(), updated_at = now(), status = 'cancelled' where id = %s", (order_id,))
    execute("update sales_order_items set deleted_at = now(), updated_at = now() where order_id = %s", (order_id,))
    return {"ok": True, "id": order_id, "number": order["number"]}


@app.get("/billing", dependencies=[Depends(require_token)])
def billing(status: str | None = None):
    if status:
        return fetch_all(
            "select * from billing_invoices where status = %s and deleted_at is null order by due_date asc",
            (status,),
        )
    return fetch_all("select * from billing_invoices where deleted_at is null order by due_date asc")


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
def delete_mobile_customer(customer_id: str, user: dict[str, Any] = Depends(require_seller_session)) -> dict[str, Any]:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Apenas administrador pode excluir clientes.")
    row_count = execute("update customers set deleted_at = now(), active = false, updated_at = now() where id = %s and deleted_at is null", (customer_id,))
    if row_count == 0:
        raise HTTPException(status_code=404, detail="Cliente nao encontrado.")
    return {"ok": True, "id": customer_id}


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
        return fetch_all(
            """
            select billing.*
            from billing_invoices billing
            where billing.deleted_at is null
            order by billing.due_date asc
            """
        )
    return fetch_all(
        """
        select billing.*
        from billing_invoices billing
        left join sales_orders orders on orders.id = billing.order_id
        where orders.seller_id = %s and billing.deleted_at is null
        order by billing.due_date asc
        """,
        (user["id"],),
    )


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


def _save_customer(item: CustomerIn) -> dict[str, Any]:
    document = _digits_only(item.document)
    existing = None
    if item.id:
        existing = fetch_one("select id from customers where id = %s and deleted_at is null limit 1", (item.id,))
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
          order by dedupe_key, updated_at desc
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
