CREATE TABLE IF NOT EXISTS fiscal_invoices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id UUID REFERENCES sales_orders(id),
  order_number INTEGER NOT NULL,
  series INTEGER NOT NULL DEFAULT 1,
  number INTEGER NOT NULL,
  environment TEXT NOT NULL DEFAULT 'producao',
  status TEXT NOT NULL DEFAULT 'pending',
  access_key TEXT,
  protocol TEXT,
  xml_url TEXT,
  danfe_url TEXT,
  cancellation_reason TEXT,
  cancelled_at TIMESTAMPTZ,
  message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_fiscal_invoices_series_number
  ON fiscal_invoices(series, number)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_fiscal_invoices_order
  ON fiscal_invoices(order_id)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_fiscal_invoices_status
  ON fiscal_invoices(status, created_at)
  WHERE deleted_at IS NULL;
