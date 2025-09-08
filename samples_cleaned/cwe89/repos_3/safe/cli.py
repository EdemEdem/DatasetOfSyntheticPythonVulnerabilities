import sqlite3
import click
import create_db

@click.command()
@click.option('--term', required=True, help='Search term for item name')
def invsearch(term):
    conn = sqlite3.connect('inventory.db')
    cur = conn.cursor()

    sql = "SELECT id, name, quantity FROM inventory WHERE name LIKE ?"
    pattern = f"%{term}%"
    cur.execute(sql, (pattern,))

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
