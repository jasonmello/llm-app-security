create table profiles (id uuid primary key, email text, phone text, address text);
create table invoices (id uuid primary key, user_id uuid, total numeric, pdf_url text);

alter table invoices enable row level security;
create policy "read invoices" on invoices for select using (true);
-- profiles: RLS never enabled
