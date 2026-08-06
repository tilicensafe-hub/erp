ALTER TABLE products ADD COLUMN IF NOT EXISTS stock_quantity NUMERIC(12,3) NOT NULL DEFAULT 0;

ALTER TABLE billing_invoices ADD COLUMN IF NOT EXISTS issued_by_id UUID REFERENCES app_users(id);
ALTER TABLE billing_invoices ADD COLUMN IF NOT EXISTS issued_by_name TEXT;
ALTER TABLE billing_invoices ADD COLUMN IF NOT EXISTS issued_at TIMESTAMPTZ;
ALTER TABLE billing_invoices ADD COLUMN IF NOT EXISTS cancelled_by_id UUID REFERENCES app_users(id);
ALTER TABLE billing_invoices ADD COLUMN IF NOT EXISTS cancelled_by_name TEXT;
ALTER TABLE billing_invoices ADD COLUMN IF NOT EXISTS cancelled_at TIMESTAMPTZ;
ALTER TABLE billing_invoices ADD COLUMN IF NOT EXISTS cancellation_reason TEXT;
