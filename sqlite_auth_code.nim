# SQLite Authentication Implementation (Alternative)
# This replaces the file-based authentication with SQLite

import db_sqlite

# --- SQLite Database Authentication ---
var db: DbConn

proc initDatabase(): void =
  try:
    db = open("users.db", "", "", "")
    echo "✅ SQLite database connected"
    
    # Ensure schema exists
    db.exec(sql"""
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        aws_access_key TEXT NOT NULL,
        aws_secret_key TEXT NOT NULL,
        bucket_name TEXT NOT NULL,
        endpoint TEXT DEFAULT 's3.tebi.io',
        region TEXT DEFAULT 'us-east-1',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME,
        is_active BOOLEAN DEFAULT 1
      )
    """)
    
    db.exec(sql"CREATE INDEX IF NOT EXISTS idx_username ON users(username)")
    echo "📊 Database schema validated"
    
  except Exception as e:
    echo "❌ Database connection failed: ", e.msg
    quit(1)

proc getUserRecordFromDB(username: string): UserRecord =
  try:
    let row = db.getRow(sql"""
      SELECT username, password, aws_access_key, aws_secret_key, 
             bucket_name, endpoint, region 
      FROM users 
      WHERE username = ? AND is_active = 1
    """, username)
    
    if row[0] == "":
      raise newException(ValueError, "User not found")
    
    result = UserRecord(
      username: row[0],
      password: row[1], 
      accessKey: row[2],
      secretKey: row[3],
      bucketName: row[4],
      endpoint: row[5],
      region: row[6]
    )
    
    # Update last login
    db.exec(sql"UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = ?", username)
    
  except Exception as e:
    echo "❌ Database query error: ", e.msg
    raise newException(ValueError, "User lookup failed")

proc addUser(username, password, accessKey, secretKey, bucketName: string, 
             endpoint: string = "s3.tebi.io", region: string = "us-east-1"): bool =
  try:
    db.exec(sql"""
      INSERT INTO users (username, password, aws_access_key, aws_secret_key, 
                        bucket_name, endpoint, region) 
      VALUES (?, ?, ?, ?, ?, ?, ?)
    """, username, password, accessKey, secretKey, bucketName, endpoint, region)
    echo "✅ User added: ", username
    return true
  except Exception as e:
    echo "❌ Failed to add user: ", e.msg
    return false

proc listUsers(): seq[string] =
  try:
    let rows = db.getAllRows(sql"""
      SELECT username, bucket_name, created_at, last_login 
      FROM users 
      WHERE is_active = 1 
      ORDER BY username
    """)
    
    result = newSeq[string]()
    for row in rows:
      let lastLogin = if row[3] == "": "Never" else: row[3]
      result.add(fmt"{row[0]} | {row[1]} | Created: {row[2]} | Last: {lastLogin}")
    
  except Exception as e:
    echo "❌ Failed to list users: ", e.msg
    result = @[]

proc deactivateUser(username: string): bool =
  try:
    db.exec(sql"UPDATE users SET is_active = 0 WHERE username = ?", username)
    echo "🔒 User deactivated: ", username
    return true
  except Exception as e:
    echo "❌ Failed to deactivate user: ", e.msg
    return false

# Replace the loadUsersFromFile() call with:
# initDatabase()

# Replace getUserRecord() with:
# getUserRecordFromDB()