# Configuration settings
import os

class Config:
    DB_PATH = os.path.join(os.path.dirname(__file__), 'instance', 'formulas.sqlite3')
    DEBUG = True
    SUPERSECRET_VARIABLE = "oh no you found my secret"