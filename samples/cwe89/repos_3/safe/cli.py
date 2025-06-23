#!/usr/bin/env python3
"""
Inventory Search CLI (Safe)
Uses parameterized queries with '?' to prevent SQL injection.
"""
import sqlite3
import click

@click.command()
@click.option('--term', required=True, help='Search term for item name')
def invsearch(term):
    """Search inventory for items whose name contains TERM."""
    conn = sqlite3.connect('inventory.db')
    cur = conn.cursor()

    # --- SAFE: parameterized query ---
    # The '?' placeholder ensures the term is treated literally.
    sql = "SELECT id, name, quantity FROM inventory WHERE name LIKE ?"
    pattern = f"%{term}%"
    click.echo(f"Executing parameterized query.")
    cur.execute(sql, (pattern,))

    rows = cur.fetchall()
    if rows:
        for item_id, name, qty in rows:
            click.echo(f"{item_id}\t{name}\t{qty}")
    else:
        click.echo("No matches found.")

    conn.close()

if __name__ == '__main__':
    invsearch()
