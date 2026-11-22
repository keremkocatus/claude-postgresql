-- Sample data for the dev stack (compose.dev.yml). The postgres image runs this once, as the superuser, in the
-- database "shop" when its volume is empty. The tables belong to shop_owner, as an application's tables would.
CREATE ROLE shop_owner NOLOGIN;
GRANT CREATE ON SCHEMA public TO shop_owner;
SET ROLE shop_owner;

CREATE TABLE customers (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name text NOT NULL,
  email text NOT NULL UNIQUE,
  country text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE products (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  sku text NOT NULL UNIQUE,
  name text NOT NULL,
  price numeric(10, 2) NOT NULL CHECK (price >= 0),
  stock int NOT NULL DEFAULT 0
);
CREATE TABLE orders (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  customer_id bigint NOT NULL REFERENCES customers (id),
  status text NOT NULL CHECK (status IN ('new', 'paid', 'shipped', 'cancelled')),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE order_items (
  order_id bigint NOT NULL REFERENCES orders (id) ON DELETE CASCADE,
  product_id bigint NOT NULL REFERENCES products (id),
  quantity int NOT NULL CHECK (quantity > 0),
  unit_price numeric(10, 2) NOT NULL,
  PRIMARY KEY (order_id, product_id)
);
CREATE INDEX orders_customer_idx ON orders (customer_id);
CREATE INDEX orders_created_idx ON orders (created_at);
COMMENT ON TABLE orders IS 'Customer orders; status goes new -> paid -> shipped (or cancelled)';

INSERT INTO customers (name, email, country, created_at)
SELECT 'Customer ' || n, 'customer' || n || '@example.com', (ARRAY['DE', 'TR', 'NL', 'US', 'FR'])[1 + n % 5],
       now() - (n % 365) * interval '1 day'
FROM generate_series(1, 200) AS n;

INSERT INTO products (sku, name, price, stock)
SELECT 'SKU-' || lpad(n::text, 4, '0'), 'Product ' || n, (5 + (n * 37) % 200) + 0.99, (n * 13) % 100
FROM generate_series(1, 30) AS n;

INSERT INTO orders (customer_id, status, created_at)
SELECT 1 + (n * 7919) % 200, (ARRAY['new', 'paid', 'shipped', 'cancelled'])[1 + n % 4],
       now() - (n % 720) * interval '1 hour'
FROM generate_series(1, 1000) AS n;

INSERT INTO order_items (order_id, product_id, quantity, unit_price)
SELECT o.id, p.id, 1 + (o.id + k) % 5, p.price
FROM orders AS o
CROSS JOIN generate_series(1, 1 + (o.id % 3)::int) AS k
JOIN products AS p ON p.id = 1 + (o.id * k * 31) % 30
ON CONFLICT DO NOTHING;

RESET ROLE;
ANALYZE;
