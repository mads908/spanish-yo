-- Run once in Supabase → SQL Editor.
-- Lets an account that was created without a password pick one the first time it logs in.
-- Only works while the account has no password yet; after that the normal login is the only way in.
create or replace function public.claim_account(p_email text, p_password text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  n int;
begin
  if length(p_password) < 6 then
    return false;
  end if;
  update auth.users
     set encrypted_password = extensions.crypt(p_password, extensions.gen_salt('bf')),
         updated_at = now()
   where lower(email) = lower(p_email)
     and coalesce(encrypted_password, '') = '';
  get diagnostics n = row_count;
  return n = 1;
end;
$$;

revoke all on function public.claim_account(text, text) from public;
grant execute on function public.claim_account(text, text) to anon, authenticated;
