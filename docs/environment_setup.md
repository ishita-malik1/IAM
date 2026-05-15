# Environment setup

For **Microsoft Graph app registration**, **permissions**, **`.env`**, and **connectivity checks**, use the single operator guide:

→ **[User guide](user_guide.md)** · Product rationale: **[Product thinking](product_thinking.md)**

### Optional: developer / demo tenant

If you need an isolated Entra directory for safe testing, use a **[Microsoft 365 developer program](https://developer.microsoft.com/microsoft-365/dev-program)** tenant (subject to Microsoft’s current program terms). IAM Risk Digest does not provision demo users or roles for you—it only reads whatever exists in the tenant you point `AZURE_TENANT_ID` at.
