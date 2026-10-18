-- Run once in Supabase → SQL Editor.
-- Lets an account flagged with app_metadata.needs_password = true pick its password the first
-- time it logs in. The flag is removed when the password is set, so it only works once.
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
         raw_app_meta_data = coalesce(raw_app_meta_data, '{}'::jsonb) - 'needs_password',
         updated_at = now()
   where lower(email) = lower(p_email)
     and raw_app_meta_data->>'needs_password' = 'true';
  get diagnostics n = row_count;
  return n = 1;
end;
$$;

revoke all on function public.claim_account(text, text) from public;
grant execute on function public.claim_account(text, text) to anon, authenticated;
