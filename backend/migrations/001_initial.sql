CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS app_users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  local_id INTEGER,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'seller')),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS customers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  local_id INTEGER,
  name TEXT NOT NULL,
  trade_name TEXT,
  document TEXT,
  state_registration TEXT,
  address TEXT,
  phone TEXT,
  whatsapp TEXT,
  email TEXT,
  notes TEXT,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_customers_document ON customers(document);
CREATE UNIQUE INDEX IF NOT EXISTS idx_customers_document_unique ON customers(document) WHERE document IS NOT NULL AND document <> '';
CREATE INDEX IF NOT EXISTS idx_customers_updated_at ON customers(updated_at);

CREATE TABLE IF NOT EXISTS products (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  local_id INTEGER,
  code TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL,
  category TEXT,
  unit TEXT NOT NULL DEFAULT 'UN',
  price NUMERIC(12,2) NOT NULL DEFAULT 0,
  cost NUMERIC(12,2),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_products_updated_at ON products(updated_at);

CREATE TABLE IF NOT EXISTS sales_orders (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  local_id INTEGER,
  number INTEGER NOT NULL,
  customer_id UUID REFERENCES customers(id),
  customer_local_id INTEGER,
  customer_name TEXT NOT NULL,
  seller_id UUID REFERENCES app_users(id),
  seller_local_id INTEGER,
  seller_name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  discount_type TEXT NOT NULL DEFAULT 'value',
  discount NUMERIC(12,2) NOT NULL DEFAULT 0,
  payment_type TEXT NOT NULL DEFAULT 'cash',
  cash_payment_method TEXT NOT NULL DEFAULT 'money',
  credit_card_installments INTEGER NOT NULL DEFAULT 1,
  credit_card_fee_percent NUMERIC(6,2) NOT NULL DEFAULT 0,
  boleto_terms TEXT NOT NULL DEFAULT '',
  extinguisher_validity DATE,
  subtotal NUMERIC(12,2) NOT NULL DEFAULT 0,
  total NUMERIC(12,2) NOT NULL DEFAULT 0,
  notes TEXT,
  status TEXT NOT NULL DEFAULT 'draft',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_sales_orders_number ON sales_orders(number);
CREATE INDEX IF NOT EXISTS idx_sales_orders_updated_at ON sales_orders(updated_at);
CREATE INDEX IF NOT EXISTS idx_sales_orders_seller ON sales_orders(seller_id, seller_local_id);

CREATE TABLE IF NOT EXISTS sales_order_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  local_id INTEGER,
  order_id UUID REFERENCES sales_orders(id) ON DELETE CASCADE,
  order_local_id INTEGER,
  product_id UUID REFERENCES products(id),
  product_local_id INTEGER,
  code TEXT NOT NULL,
  description TEXT NOT NULL,
  unit TEXT NOT NULL DEFAULT 'UN',
  quantity NUMERIC(12,3) NOT NULL DEFAULT 0,
  unit_price NUMERIC(12,2) NOT NULL DEFAULT 0,
  total NUMERIC(12,2) NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_sales_order_items_order ON sales_order_items(order_id, order_local_id);

CREATE TABLE IF NOT EXISTS billing_invoices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  local_id INTEGER,
  order_id UUID REFERENCES sales_orders(id),
  order_local_id INTEGER,
  order_number INTEGER NOT NULL,
  customer_id UUID REFERENCES customers(id),
  customer_local_id INTEGER,
  customer_name TEXT NOT NULL,
  amount NUMERIC(12,2) NOT NULL,
  due_date DATE NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  cora_id TEXT,
  cora_code TEXT,
  bank_slip_url TEXT,
  digitable_line TEXT,
  barcode TEXT,
  pix_copy_paste TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_billing_status_due ON billing_invoices(status, due_date);
CREATE INDEX IF NOT EXISTS idx_billing_updated_at ON billing_invoices(updated_at);

CREATE TABLE IF NOT EXISTS sync_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id TEXT NOT NULL,
  entity TEXT NOT NULL,
  entity_id UUID,
  local_id INTEGER,
  action TEXT NOT NULL,
  payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sync_events_created_at ON sync_events(created_at);
