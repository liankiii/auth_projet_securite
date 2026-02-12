# auth_projet_securite

Petit projet Flask pour un mini systeme de login/register sans base de donnees.
Les comptes sont stockes dans un fichier JSON local.

## Fonctionnalites
- inscription et connexion
- mots de passe haches (bcrypt)
- messages flash
- admin: reset et suppression d un compte

## Demarrage
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export SECRET_KEY="change_me"
export ADMIN_TOKEN="mon_token_secret"
flask run