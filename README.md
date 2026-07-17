# mbf-server

## Account Approval Flow

- Public self-registration is disabled.
- `POST /auth/register` is restricted to authenticated admins and requires `x-api-key`.
- Users created by admin are approved immediately.
- For first-time setup, bootstrap registration is allowed only when there are no users yet and `userId` is listed in `ADMIN_USER_IDS` (also requires `x-api-key`).

Example:

```env
ADMIN_USER_IDS=admin,prajjwal
```
