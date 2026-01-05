Com base nos requisitos dos PDFs das disciplinas  e na estrutura do seu projeto, preparei um template de `README.md` profissional e completo para o seu repositório do **Ser# Chat Server - Segurança da Informação (E2EE)

Este projeto consiste em um **Servidor de Chat Seguro** desenvolvido para a disciplina de Segurança da Informação do curso de Engenharia da Computação (UFRPE/UABJ). O sistema implementa um protocolo de comunicação robusto com criptografia ponta-a-ponta (E2EE) entre clientes, garantindo confidencialidade, integridade e autenticidade.

## Contexto Acadêmico

* 
**Instituição:** Universidade Federal Rural de Pernambuco (UFRPE) 


* 
**Unidade:** Unidade Acadêmica de Belo Jardim (UABJ) 


* 
**Disciplina:** Segurança da Informação 


* **Professor:** [Ygor Amaral](https://github.com/ygoramaral)

## Funcionalidades Principal

* 
**Arquitetura Multithread:** Suporte a múltiplos clientes simultâneos via sockets TCP.


* 
**Registro e Autenticação Segura:** Hashing de senhas utilizando **Argon2** com salts individuais por usuário.


* 
**Criptografia de Canal:** Toda a comunicação entre Cliente e Servidor é cifrada com **AES-256** e autenticada via **HMAC-SHA256**.


* 
**Handshake Criptográfico:** Negociação de chaves de sessão efêmeras via **Diffie-Hellman (DHE)** e derivação por **HKDF**.


* 
**Roteamento E2EE:** O servidor roteia mensagens criptografadas entre usuários sem ter acesso ao conteúdo original (Segredo de Encaminhamento).


* 
**Persistência de Dados:** Armazenamento de usuários e mensagens offline em banco de dados MySQL.



## Tecnologias Utilizadas

* **Linguagem:** Python 3.10+
* 
**Banco de Dados:** MySQL 8.0 


* **Containerização:** Docker & Docker Compose
* **Criptografia:** Bibliotecas `cryptography` e `argon2-cffi`

## Repositórios Relacionados

* **Repositório do Cliente (Flutter/Desktop):** [Cliente Flutter](https://github.com/claraaqn/Cliente-Flutter)

## Como Executar (Docker)

Siga os passos abaixo para subir o ambiente completo (Servidor + Banco de Dados):

1. **Clone este repositório:**
```bash
git clone <link-deste-repositorio>
cd servidor

```


2. **Configure as variáveis de ambiente:**
Crie um arquivo `.env` na raiz do projeto (use o `.env.example` como base):
```bash
cp .env.example .env

```


*Certifique-se de definir `DB_HOST=db` para o funcionamento correto dentro do Docker.*
3. **Inicie os containers:**
```bash
docker-compose up --build

```


4. **Verificação:**
O servidor estará pronto para receber conexões quando o log exibir:
` Servidor pronto para conexões!` nas portas `8081` (TCP) e `8080` (WebSocket).

## Arquitetura de Segurança

O projeto segue rigorosamente os requisitos de segurança definidos:

* 
**Confidencialidade:** AES-256 em modo CBC/GCM.


* 
**Integridade:** HMAC-SHA256 para detectar qualquer alteração nos pacotes.


* 
**Autenticação Mútua:** Uso de assinaturas digitais (RSA-PSS ou Ed25519) após o handshake inicial.


* 
**Efemeridade:** Chaves de sessão expiram por tempo (60 min) ou volume de mensagens (100 msgs).



---

**Desenvolvido por:** [Seu Nome Aqui]
*Estudante de Engenharia da Computação - UFRPE*
