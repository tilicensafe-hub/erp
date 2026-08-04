ALTER TABLE sales_orders
  ADD COLUMN IF NOT EXISTS credit_card_installments INTEGER NOT NULL DEFAULT 1;

ALTER TABLE sales_orders
  ADD COLUMN IF NOT EXISTS credit_card_fee_percent NUMERIC(6,2) NOT NULL DEFAULT 0;
