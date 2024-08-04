from sqlalchemy import create_engine, text

# Remplace l'URL de connexion par la tienne
engine = create_engine('postgresql://postgres.jmiotireachftycaknlh:Marti%4012345nous@aws-0-eu-central-1.pooler.supabase.com:6543/postgres')

# Essayer de se connecter et d'exécuter une requête simple
with engine.connect() as connection:
    result = connection.execute(text("SELECT 1"))
    print(result.fetchone())