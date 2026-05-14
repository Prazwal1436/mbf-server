# mbf-server

## Account Approval Flow

- New registrations are created with `isApproved = false` by default.
- Unapproved users cannot log in.
- Admins approve pending users from the app's admin panel.
- At least one bootstrap admin is required. Set `ADMIN_USER_IDS` in the backend environment to a comma-separated list of user IDs that should auto-register as approved admins.

Example:

```env
ADMIN_USER_IDS=admin,prajjwal
```
