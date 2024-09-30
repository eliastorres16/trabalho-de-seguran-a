import sqlite3

conn = sqlite3.connect('UsersData.db')

cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS Users (
    Id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    User TEXT NOT NULL,
    Password TEXT NOT NULL,
    Email TEXT NOT NULL,
    Name TEXT NOT NULL  
);
""")

print("Conectado ao banco de dados")