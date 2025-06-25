#!/usr/bin/env python3
"""
Inventory Search CLI (Vulnerable)
Constructs the LIKE query via string concatenation.
DO NOT USE IN PRODUCTION.
"""
import sqlite3
import click
import create_db

@click.command()
@click.option('--term', required=True, help='Search term for item name')
def invsearch(term):
    """Search inventory for items whose name contains TERM."""
    # connect to SQLite database file (assumes inventory.db in cwd)
    conn = sqlite3.connect('inventory.db')
    cur = conn.cursor()

    # --- VULNERABLE: direct string concatenation ---
    # If term is "' OR '1'='1", this will match everything.
    sql = f"SELECT id, name, quantity FROM inventory WHERE name LIKE '%{term}%'"
    cur.execute(sql)

    rows = cur.fetchall()
    if rows:
        for item_id, name, qty in rows:
            click.echo(f"{item_id}\t{name}\t{qty}")
    else:
        click.echo("No matches found.")

    conn.close()

if __name__ == '__main__':
    create_db.init_db()
    invsearch()
