# Licensafe Backend

Backend inicial para sincronizacao online do ERP Licensafe usando PostgreSQL/Neon.

## Importante

Nao grave a URL real do Neon dentro do codigo. Use `.env`.

Como a URL do banco foi compartilhada no chat, recomendo trocar/regenerar a senha no painel do Neon depois que tudo estiver funcionando.

## Configurar

1. Copie `.env.example` para `.env`.
2. Coloque sua `DATABASE_URL` do Neon.
3. Defina um `API_TOKEN` forte.
4. No painel do Neon, abra o SQL Editor e execute:

```sql
\i migrations/001_initial.sql
```

Se o editor do Neon nao aceitar `\i`, abra o arquivo `migrations/001_initial.sql`, copie tudo e cole no SQL Editor.

Depois execute tambem:

- `migrations/002_sync_upserts.sql`
- `migrations/003_mobile_sales.sql`

## Rodar localmente

```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Teste:

```powershell
curl http://127.0.0.1:8000/health
```

## Deploy no Render

Configuracao manual:

- Runtime: `Python`
- Root Directory: `backend`
- Build Command: `pip install -r requirements.txt`
- Start Command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`

Environment Variables:

- `DATABASE_URL`: URL do Neon PostgreSQL
- `API_TOKEN`: token forte criado por voce
- `APP_ENV`: `production`

## Segurança

Todas as rotas de dados exigem o header:

```text
Authorization: Bearer SEU_API_TOKEN
```

## Rotas ja preparadas para o app vendedor

- `POST /auth/login`: login do vendedor usando e-mail e senha sincronizados da Central.
- `GET /mobile/bootstrap`: baixa clientes e produtos ativos para o celular.
- `POST /orders`: cria pedido online com produtos.
- `GET /orders`: lista pedidos.
- `GET /orders/{id}/items`: lista itens de um pedido.
- `GET /billing`: lista boletos/faturamento.

Na Central, o botao de sincronizacao envia:

- usuarios/vendedores
- clientes
- produtos com dados fiscais
