CREATE UNIQUE INDEX IF NOT EXISTS idx_customers_document_unique
ON customers(document)
WHERE document IS NOT NULL AND document <> '';

ALTER TABLE customers ADD CONSTRAINT customers_document_unique UNIQUE (document);
