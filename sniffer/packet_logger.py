import sqlite3

def init_db():
    conn = sqlite3.connect('../packets.db')  # go up one level if inside /sniffer
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        protocol TEXT,
        length INTEGER
    )
    """)
    
    conn.commit()
    conn.close()

def insert_packet(timestamp, src_ip, dst_ip, protocol, length):
    conn = sqlite3.connect('../packets.db')  # go up one level if inside /sniffer
    cursor = conn.cursor()
    
    cursor.execute("""
    INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length)
    VALUES (?, ?, ?, ?, ?)
    """, (timestamp, src_ip, dst_ip, protocol, length))
    
    conn.commit()
    conn.close()
