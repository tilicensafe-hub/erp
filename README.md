# Licensafe ERP

ERP offline para Windows feito em Flutter + SQLite, com estrutura preparada para Android/tablets e futura troca do banco local por um backend online.

## Funcionalidades implementadas

- Login com perfis Administrador e Vendedor.
- Configuracoes da empresa, impressora, numeracao e tema.
- CRUD de clientes, produtos e usuarios.
- Consulta opcional de CNPJ quando houver internet.
- Pedidos com cliente, vendedor, itens, desconto em valor ou percentual, rascunho e finalizacao.
- PDF para A4, termica 80mm e termica 58mm.
- Relatorios basicos de pedidos, vendas por vendedor, clientes e produtos.
- Backup e restauracao do banco SQLite local.

## Como executar

Instale o Flutter com suporte a Windows Desktop. No Windows, tambem habilite o Modo de Desenvolvedor e instale o Visual Studio com a carga **Desenvolvimento para desktop com C++**.

Se o Flutter estiver em `C:\flutter`, adicione `C:\flutter\bin` ao PATH do Windows ou use o caminho completo nos comandos:

```powershell
flutter create --platforms=windows .
flutter pub get
flutter run -d windows
```

Para gerar o executavel:

```powershell
flutter build windows
```

Usuario inicial:

- E-mail: `admin@licensafe.local`
- Senha: `admin123`
