import sqlite3
import click

DB_PATH = 'inventory.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='inventory';"
    )
    if not cur.fetchone():
        click.echo("Table 'inventory' not found—creating it now.")
        cur.execute("""
            CREATE TABLE inventory (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                quantity INTEGER NOT NULL
            );
        """)
        conn.commit()


    cur.execute("SELECT COUNT(*) FROM inventory;")
    count = cur.fetchone()[0]
    if count == 0:
        click.echo("Populating 'inventory' with sample data.")
        samples = [
            ('widget', 42),
            ('gadget', 17),
            ('thingamajig', 3),
        ]
        for name, qty in samples:
            cur.execute(
                "INSERT INTO inventory (name, quantity) VALUES (?, ?);",
                (name, qty)
            )
        conn.commit()

    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='api_keys';"
    )
    if not cur.fetchone():
        click.echo("Table 'api_keys' not found—creating it now.")
        cur.execute("""
            CREATE TABLE api_keys (
                id INTEGER PRIMARY KEY,
                service TEXT NOT NULL,
                api_key TEXT NOT NULL
            );
        """)
        conn.commit()

        
        click.echo("Populating 'api_keys' with secret sample data.")
        secrets = [
            ('payment_gateway', 'sk_test_51Hxxxxxx'),
            ('email_service',     'ESvc_abc123XYZ'),
            ('logging_service',   'logtok-9876543210'),
        ]
        cur.executemany(
            "INSERT INTO api_keys (service, api_key) VALUES (?, ?);",
            secrets
        )
        conn.commit()
        click.echo("Database is now initialized. Ready to run the rest of the program")
        click.echo("-----------------------------------------------------------------")

    conn.close()
    

