# 01. Authentication vs Authorization

## Notes

### The one-line answer

- **Authentication (AuthN)** asks **"Who are you?"**
- **Authorization (AuthZ)** asks **"What are you allowed to do?"**

Authentication always happens **first**. You can't decide what someone may do until you know who they are.

---

### A real-life example: an office building

Picture yourself walking into a big office:

1. **At the front gate**, the security guard checks your **ID card**.
   They're confirming that you really are _Rahul Sharma_.
   👉 That's **Authentication**.

2. **Inside the building**, you tap your card on the door to the **server room**.
   The door stays shut, because only IT staff can go in.
   👉 That's **Authorization**.

The guard knew exactly who you were (authentication passed), but you still couldn't get in (authorization failed). **Two separate checks.**

---

### A real-life example: Instagram

| Action                                       | Which check?   | Why                                          |
| -------------------------------------------- | -------------- | -------------------------------------------- |
| You type your username + password and log in | Authentication | Instagram is confirming it's really you      |
| You edit **your own** post                   | Authorization  | You own it, so you're **allowed**            |
| You try to delete **someone else's** post    | Authorization  | You're logged in, but you're **not allowed** |
| You open the admin dashboard                 | Authorization  | Only Instagram employees have access         |

---

### Side-by-side comparison

|                          | Authentication                    | Authorization                       |
| ------------------------ | --------------------------------- | ----------------------------------- |
| Question it answers      | Who are you?                      | What can you do?                    |
| When it happens          | First                             | After authentication                |
| What it checks           | Password, OTP, fingerprint, token | Roles, permissions, ownership       |
| Can the user change it?  | Yes (change your password)        | No (an admin or the system decides) |
| Example                  | Logging in with email + password  | Only admins can delete users        |
| HTTP error when it fails | **401 Unauthorized**              | **403 Forbidden**                   |
| Short name               | AuthN                             | AuthZ                               |

---

### How it works in a backend (step by step)

When a request reaches your server:

```
Request comes in
      │
      ▼
┌─────────────────────┐
│  1. Authentication  │   "Who is sending this?"
│  Check token/cookie │
└─────────────────────┘
      │
      ├── No token / bad token ──► 401 Unauthorized  ("Please log in")
      │
      ▼
┌─────────────────────┐
│  2. Authorization   │   "Is this user allowed to do this?"
│  Check role/owner   │
└─────────────────────┘
      │
      ├── Not allowed ──► 403 Forbidden  ("You can't do this")
      │
      ▼
   ✅ Run the actual work (send data, delete post, etc.)
```

---

### Common ways to do each

**Authentication: proving who you are**

- Something you **know**: password, PIN
- Something you **have**: phone (OTP), security key
- Something you **are**: fingerprint, face
- Login with **Google / GitHub** (OAuth / OpenID Connect)
- **Tokens / sessions**: after you log in once, a cookie or JWT proves who you are on every request

**Authorization: deciding what you can do**

- **Roles (RBAC)**: `admin` can delete users, `user` cannot
- **Ownership**: you can edit only _your own_ posts
- **Permissions**: a list like `["read:posts", "write:posts"]`
- **Rules/attributes (ABAC)**: e.g., "managers can approve expenses under ₹50,000"

_(Each of these gets its own topic later in this course.)_

---

### ⚠️ The confusing part: 401 vs 403

The HTTP names are misleading:

- **401 "Unauthorized"** actually means **"Unauthenticated"**: _I don't know who you are. Please log in._
- **403 "Forbidden"** means **"Unauthorized"**: _I know who you are, but you're not allowed._

A simple way to remember:

> **401**: "Who are you?" 🤷
> **403**: "I know you, and the answer is no." 🙅

---

### Common beginner mistakes

1. **Only checking login, never checking permission.**
   The user is logged in, so you let them call `DELETE /posts/42`, even though post 42 belongs to someone else. This is one of the most common real-world security bugs (called **IDOR / Broken Access Control**).

2. **Trusting the frontend to hide buttons.**
   Hiding the "Delete" button in the UI is **not** authorization. Anyone can call your API directly with Postman or curl. **Always check on the server.**

3. **Mixing up 401 and 403.**
   Return 401 when the user isn't logged in, and 403 when they're logged in but not allowed.

4. **Trusting the role the client sends.**
   Never do `if (req.body.role === "admin")`. Read the role from **your database** or a **signed token**, never from what the user typed.

---

### Interview questions

1. **What is the difference between authentication and authorization?**
   Authentication verifies identity ("who are you?"). Authorization checks permissions ("what can you do?"). Authentication comes first.

2. **Can you have authorization without authentication?**
   Mostly no, because you need to know _who_ someone is before deciding what they can do. (One exception: rules for anonymous "guest" users, like "anyone can read public posts.")

3. **401 vs 403?**
   401 means not authenticated (missing or invalid credentials). 403 means authenticated but not permitted.

4. **Give an example of each from an app you've used.**
   Logging into Gmail is authentication. Being unable to open another person's inbox is authorization.

5. **Where should authorization checks happen, frontend or backend?**
   Backend, always. The frontend can hide things for a nicer UX, but only the server can enforce rules.

---

### Quick recap

- **AuthN** = identity = "Who are you?" = login = **401** if it fails
- **AuthZ** = permission = "What can you do?" = roles/ownership = **403** if it fails
- AuthN comes first, then AuthZ
- **Always** check both on the server
