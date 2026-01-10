import jester, json, tables, times, strutils, httpclient, nimcrypto, uri, strformat, xmltree, xmlparser, std/sysrand, net, os

settings:
  port = Port(8082)

type
  UserSession = object
    accessKey: string
    secretKey: string
    bucketName: string
    region: string
    endpoint: string
    createdAt: DateTime
    username: string  # Track username for admin checks
    isAdmin: bool     # Track admin status

# Response cache to reduce redundant S3 calls
type
  CacheEntry = object
    data: JsonNode
    timestamp: DateTime
    
var responseCache = initTable[string, CacheEntry]()
const CACHE_DURATION = initDuration(minutes = 2)

proc getCacheKey(session: UserSession, prefix: string): string =
  return session.accessKey[0..7] & ":" & prefix

proc getCachedResponse(session: UserSession, prefix: string): JsonNode =
  let key = getCacheKey(session, prefix)
  if key in responseCache:
    let entry = responseCache[key]
    if now() - entry.timestamp < CACHE_DURATION:
      echo "💾 Using cached response for: ", prefix
      return entry.data
  return nil

proc setCachedResponse(session: UserSession, prefix: string, data: JsonNode) =
  let key = getCacheKey(session, prefix)
  responseCache[key] = CacheEntry(data: data, timestamp: now())
  echo "💾 Cached response for: ", prefix

proc invalidateCache(session: UserSession, prefix: string = "") {.gcsafe.} =
  {.gcsafe.}:
    # Invalidate cache entries that might be affected by the change
    var keysToRemove: seq[string] = @[]
    let sessionPrefix = session.accessKey[0..7] & ":"
    
    for key in responseCache.keys():
      if key.startsWith(sessionPrefix):
        # Remove if it's the exact prefix or a parent directory
        let cachedPrefix = key.split(":")[1]
        if cachedPrefix == prefix or prefix.startsWith(cachedPrefix) or cachedPrefix.startsWith(prefix):
          keysToRemove.add(key)
    
    for key in keysToRemove:
      responseCache.del(key)
      echo "🗑️ Invalidated cache for: ", key

# S3 API compatibility types
type
  S3ApiTier = enum
    Tier1_ListV2,    # list-type=2 with delimiter (modern S3)
    Tier2_Legacy,    # delimiter only (legacy S3) 
    Tier3_Simple     # prefix only (compatibility mode)

# Forward declarations
proc sendS3Request(session: UserSession, httpMethod: string, key: string, query: string = "", body: string = ""): Response
proc parseS3ListWithFolders(xml: string): JsonNode
proc parseS3ListSimple(xml: string, currentPrefix: string): JsonNode
proc getS3Tier(session: UserSession, hasPrefix: bool): S3ApiTier
proc cacheS3Tier(session: UserSession, hasPrefix: bool, tier: S3ApiTier)

# --- Helper Functions ---
proc isAdminSubdomain(host: string): bool =
  # Check if host starts with "admin." or is exactly "admin"
  return host.startsWith("admin.") or host == "admin"

proc extractPath(key: string): string =
  # Extract folder path from S3 key
  let parts = key.split("/")
  if parts.len > 1:
    return parts[0..^2].join("/") & "/"
  return ""

proc createFolder(session: UserSession, folderPath: string): bool =
  # Create a folder in S3 by creating an empty object with trailing /
  try:
    let folderKey = if folderPath.endsWith("/"): folderPath else: folderPath & "/"
    echo "📁 Creating folder with key: ", folderKey
    
    # Try to create folder with empty content
    let resp = sendS3Request(session, "PUT", folderKey, "", "")
    echo "📁 Create folder response: ", resp.code, " ", resp.status
    echo "📁 Create folder body: ", resp.body
    
    # Some S3 implementations return 200, others return 201 for PUT
    if resp.code.is2xx:
      # Invalidate cache for parent directories
      let parentPath = extractPath(folderKey)
      invalidateCache(session, parentPath)
      invalidateCache(session, "")  # Also invalidate root cache
      return true
    return false
  except Exception as e:
    echo "❌ Exception in createFolder: ", e.msg
    return false

# --- File-Based Authentication ---
type
  UserRecord = object
    username: string
    password: string
    accessKey: string
    secretKey: string
    bucketName: string
    endpoint: string
    region: string
    isAdmin: bool  # New field for admin privileges

var usersDatabase = initTable[string, UserRecord]()

# Admin configuration - set the admin username here
const ADMIN_USERNAME = "momo"  # Change this to set which user is admin

proc loadUsersFromFile(): void =
  # Load users from users.txt file
  if fileExists("users.txt"):
    echo "📁 Loading users from users.txt file..."
    for line in lines("users.txt"):
      if line.len > 0 and not line.startsWith("#"):
        let parts = line.split(":")
        if parts.len >= 7:
          let username = parts[0].strip()
          let user = UserRecord(
            username: username,
            password: parts[1].strip(),
            accessKey: parts[2].strip(),
            secretKey: parts[3].strip(),
            bucketName: parts[4].strip(),
            endpoint: parts[5].strip(),
            region: parts[6].strip(),
            isAdmin: username == ADMIN_USERNAME
          )
          usersDatabase[user.username] = user
          echo "✅ Loaded user: ", user.username, if user.isAdmin: " (ADMIN)" else: ""
        elif parts.len >= 6:
          # Default region if not specified
          let username = parts[0].strip()
          let user = UserRecord(
            username: username,
            password: parts[1].strip(),
            accessKey: parts[2].strip(),
            secretKey: parts[3].strip(),
            bucketName: parts[4].strip(),
            endpoint: parts[5].strip(),
            region: "us-east-1",
            isAdmin: username == ADMIN_USERNAME
          )
          usersDatabase[user.username] = user
          echo "✅ Loaded user: ", user.username, if user.isAdmin: " (ADMIN)" else: ""
  else:
    echo "❌ users.txt file not found. Creating example file..."
    writeFile("users.txt", """# Panda Cloud Users Database
# Format: username:password:aws_access_key:aws_secret_key:bucket_name:endpoint:region
# Lines starting with # are comments

# Example user (replace with your credentials):
# demo:demo123:your_access_key:your_secret_key:your_bucket:s3.tebi.io:us-east-1
""")

proc getUserRecord(username: string): UserRecord =
  if username in usersDatabase:
    return usersDatabase[username]
  else:
    raise newException(ValueError, "User not found")

proc requireAdmin(session: UserSession) =
  if not session.isAdmin:
    raise newException(ValueError, "Admin privileges required")

proc saveUsersToFile(): void {.gcsafe.} =
  {.gcsafe.}:
    var content = """# Panda Cloud Users Database
# Format: username:password:aws_access_key:aws_secret_key:bucket_name:endpoint:region
# Lines starting with # are comments

"""
    
    for username, user in usersDatabase:
      content.add(fmt"{user.username}:{user.password}:{user.accessKey}:{user.secretKey}:{user.bucketName}:{user.endpoint}:{user.region}" & "\n")
    
    content.add("""
# Add new users in the same format:
# username:password:access_key:secret_key:bucket:endpoint:region""")
    
    writeFile("users.txt", content)
    echo "✅ Users database saved to users.txt"

proc addUserToDatabase(username, password, accessKey, secretKey, bucketName, endpoint, region: string): bool {.gcsafe.} =
  {.gcsafe.}:
    if username in usersDatabase:
      return false  # User already exists
    
    usersDatabase[username] = UserRecord(
      username: username,
      password: password,
      accessKey: accessKey,
      secretKey: secretKey,
      bucketName: bucketName,
      endpoint: endpoint,
      region: region,
      isAdmin: username == ADMIN_USERNAME  # Set admin status based on constant
    )
    
    saveUsersToFile()
    return true

proc updateUserInDatabase(username: string, updates: Table[string, string]): bool {.gcsafe.} =
  {.gcsafe.}:
    if username notin usersDatabase:
      return false
    
    var user = usersDatabase[username]
    
    if "password" in updates:
      user.password = updates["password"]
    if "accessKey" in updates:
      user.accessKey = updates["accessKey"]
    if "secretKey" in updates:
      user.secretKey = updates["secretKey"]
    if "bucket" in updates:
      user.bucketName = updates["bucket"]
    if "endpoint" in updates:
      user.endpoint = updates["endpoint"]
    if "region" in updates:
      user.region = updates["region"]
    
    usersDatabase[username] = user
    saveUsersToFile()
    return true

proc deleteUserFromDatabase(username: string): bool {.gcsafe.} =
  {.gcsafe.}:
    if username notin usersDatabase:
      return false
    
    usersDatabase.del(username)
    saveUsersToFile()
    return true

# --- Environment Configuration (for defaults) ---
proc loadEnvConfig(): tuple[accessKey: string, secretKey: string, bucketName: string, region: string, endpoint: string] =
  result.accessKey = ""
  result.secretKey = ""
  result.bucketName = ""
  result.region = "us-east-1"
  result.endpoint = "s3.tebi.io"

let envConfig = loadEnvConfig()

# Initialize users database
loadUsersFromFile()

var sessionsStore = initTable[string, UserSession]()

# S3 API compatibility cache - remembers which API tier works for each session
var s3CompatibilityCache = initTable[string, tuple[rootList: S3ApiTier, prefixList: S3ApiTier]]()

proc getS3Tier(session: UserSession, hasPrefix: bool): S3ApiTier =
  let sessionKey = session.accessKey[0..min(7, session.accessKey.len-1)] # Use first 8 chars as key
  
  if sessionKey in s3CompatibilityCache:
    let cached = s3CompatibilityCache[sessionKey]
    return if hasPrefix: cached.prefixList else: cached.rootList
  else:
    return Tier1_ListV2  # Start with best tier

proc cacheS3Tier(session: UserSession, hasPrefix: bool, tier: S3ApiTier) =
  let sessionKey = session.accessKey[0..min(7, session.accessKey.len-1)]
  
  if sessionKey in s3CompatibilityCache:
    var cached = s3CompatibilityCache[sessionKey]
    if hasPrefix:
      cached.prefixList = tier
    else:
      cached.rootList = tier
    s3CompatibilityCache[sessionKey] = cached
  else:
    if hasPrefix:
      s3CompatibilityCache[sessionKey] = (rootList: Tier1_ListV2, prefixList: tier)
    else:
      s3CompatibilityCache[sessionKey] = (rootList: tier, prefixList: Tier1_ListV2)

# SECURE Session ID Generation
proc generateSecureSessionId(): string {.gcsafe.} =
  let bytes = urandom(16)
  result = ""
  for b in bytes: result.add(b.toHex(2))

proc getSession(sessionId: string): UserSession {.gcsafe.} =
  {.gcsafe.}:
    if sessionId in sessionsStore:
      return sessionsStore[sessionId]
    else:
      raise newException(ValueError, "Invalid session")

# --- AWS Signature V4 Implementation ---

# NEW: Get service name for Tebi (always use 's3' for compatibility)
proc getService(session: UserSession): string =
  return "s3"  # Use standard S3 service name for Tebi compatibility

# DEFENSIVE TIME CHECK (prevents hours of debugging)
proc validateSystemTime() =
  let nowUtc = now().utc
  if nowUtc.year > 2030 or nowUtc.year < 2020:
    quit("🚨 SYSTEM CLOCK IS INVALID: " & $nowUtc & " - Fix system time with 'sudo ntpdate pool.ntp.org'")
  echo "✅ System time validated: ", nowUtc

proc sha256Hex(data: string): string =
  return ($sha256.digest(data)).toLowerAscii()

proc getSignatureKey(secret, dateStamp, regionName, serviceName: string): MDigest[256] =
  let kDate = hmac(sha256, "AWS4" & secret, dateStamp)
  let kRegion = hmac(sha256, kDate.data, regionName)
  let kService = hmac(sha256, kRegion.data, serviceName)
  let kSigning = hmac(sha256, kService.data, "aws4_request")
  return kSigning

# Use virtual-hosted-style URLs for Tebi: https://bucket.endpoint/key
func getS3Url(session: UserSession, key: string): string =
  let proto = if session.endpoint.startsWith("http"): "" else: "https://"
  # For Tebi, use virtual-hosted style: bucket.endpoint/key
  return fmt"{proto}{session.bucketName}.{session.endpoint}/{key}"

# --- Presigned URL Generator ---
proc generatePresignedUrl(session: UserSession, key: string, httpMethod: string = "GET", forceDownload: bool = false): string =
  let
    datetime = now().utc
    amzDate = datetime.format("yyyyMMdd'T'HHmmss'Z'")
    dateStamp = datetime.format("yyyyMMdd")
    service = getService(session)
    region = session.region
    expires = "3600"

    algorithm = "AWS4-HMAC-SHA256"
    credentialScope = fmt"{dateStamp}/{region}/{service}/aws4_request"
    # Use virtual-hosted style host: bucket.endpoint
    host = fmt"{session.bucketName}.{session.endpoint}"
    encodedKey = key.encodeUrl(usePlus=false)

    qAlgo = fmt"X-Amz-Algorithm={algorithm}"
    qCred = fmt"X-Amz-Credential={session.accessKey.encodeUrl()}%2F{credentialScope.encodeUrl()}"
    qDate = fmt"X-Amz-Date={amzDate}"
    qExp = fmt"X-Amz-Expires={expires}"
    
    # Add response-content-disposition for downloads
    responseHeaders = if forceDownload:
        fmt"&response-content-disposition=attachment%3B%20filename%3D{key.encodeUrl()}"
      else:
        ""
    
    qSigned = "X-Amz-SignedHeaders=host"

    canonicalQueryString = fmt"{qAlgo}&{qCred}&{qDate}&{qExp}&{qSigned}{responseHeaders}"
    canonicalHeaders = fmt"host:{host}" & "\n"
    # Virtual-hosted style canonical request path: /key
    canonicalRequestPath = fmt"/{encodedKey}"
    canonicalRequest = httpMethod & "\n" & canonicalRequestPath & "\n" & canonicalQueryString & "\n" & canonicalHeaders & "\n" & "host\nUNSIGNED-PAYLOAD"

    signingKey = getSignatureKey(session.secretKey, dateStamp, region, service)
    stringToSign = algorithm & "\n" & amzDate & "\n" & credentialScope & "\n" & sha256Hex(canonicalRequest)
    signature = ($hmac(sha256, signingKey.data, stringToSign)).toLowerAscii()

    # Virtual-hosted style URL
    fullUrl = getS3Url(session, encodedKey) & fmt"?{canonicalQueryString}&X-Amz-Signature={signature}"

  return fullUrl

# --- XML Parser (Minimal) ---
proc parseS3List(xml: string): JsonNode =
  var resultArray = newJArray()
  try:
    let tree = parseXml(xml)
    
    # Find all Contents elements
    proc findContents(node: XmlNode) =
      if node.kind == xnElement and node.tag == "Contents":
        var item = newJObject()
        for child in node:
          if child.kind == xnElement:
            # Get text content from child text nodes
            var textContent = ""
            for textChild in child:
              if textChild.kind == xnText:
                textContent.add(textChild.text)
            if textContent.len > 0:
              item[child.tag] = %*textContent
        resultArray.add(item)
      
      # Recursively search child elements
      for child in node:
        if child.kind == xnElement:
          findContents(child)
    
    findContents(tree)
  except XmlError as e:
    echo "XML Parsing Error: ", e.msg
  return %*{"Contents": resultArray}

# --- Server-Side S3 Operations ---

proc sendS3Request(session: UserSession, httpMethod: string, key: string, query: string = "", body: string = ""): Response =
  let
    service = getService(session)
    region = session.region
    # Use current time (fixed time was for debugging)
    datetime = now().utc
    amzDate = datetime.format("yyyyMMdd'T'HHmmss'Z'")
    dateStamp = datetime.format("yyyyMMdd")
    # Virtual-hosted style host: bucket.endpoint
    host = fmt"{session.bucketName}.{session.endpoint}"

    # Virtual-hosted style canonical URI - when using virtual hosted style,
    # the bucket is in the host, so canonical URI is just the key path
    encodedKey = key.encodeUrl(usePlus = false)
    canonicalUri = if key.len == 0: "/" else: fmt"/{encodedKey}"

    payloadHash = sha256Hex(body)

    # For HEAD requests, don't include x-amz-content-sha256 (like boto3)  
    canonicalHeaders = if httpMethod == "HEAD":
        fmt"host:{host}" & "\n" & fmt"x-amz-date:{amzDate}" & "\n" & "\n"
      else:
        fmt"host:{host}" & "\n" & fmt"x-amz-content-sha256:{payloadHash}" & "\n" & fmt"x-amz-date:{amzDate}" & "\n" & "\n"
        
    signedHeaders = if httpMethod == "HEAD": "host;x-amz-date" else: "host;x-amz-content-sha256;x-amz-date"
    canonicalRequest = httpMethod & "\n" & canonicalUri & "\n" & query & "\n" & canonicalHeaders & signedHeaders & "\n" & payloadHash

    algorithm = "AWS4-HMAC-SHA256"
    credentialScope = fmt"{dateStamp}/{region}/{service}/aws4_request"
    stringToSign = algorithm & "\n" & amzDate & "\n" & credentialScope & "\n" & sha256Hex(canonicalRequest)
    signingKey = getSignatureKey(session.secretKey, dateStamp, region, service)
    signature = ($hmac(sha256, signingKey.data, stringToSign)).toLowerAscii()

  # Use local HTTP client with connection pooling
  let httpClient = newHttpClient(timeout = 5000)
  httpClient.headers = newHttpHeaders({
    "Authorization": fmt"{algorithm} Credential={session.accessKey}/{credentialScope}, SignedHeaders={signedHeaders}, Signature={signature}",
    "X-Amz-Date": amzDate,
    "Connection": "keep-alive",
    "User-Agent": "PandaCloud/1.0 (Nim)"
  })
  
  if httpMethod != "HEAD":
    httpClient.headers["X-Amz-Content-Sha256"] = payloadHash

  # Virtual-hosted style URL
  let url = getS3Url(session, if key.len > 0: encodedKey else: "") & (if query.len > 0: "?" & query else: "")
  echo "🌐 Making request to: ", url

  if httpMethod == "DELETE":
    httpClient.headers["Content-Length"] = "0"
  elif httpMethod == "PUT" and body.len == 0:
    # For empty PUT requests (like folder creation), set content length to 0
    httpClient.headers["Content-Length"] = "0"

  case httpMethod:
    of "GET": return httpClient.get(url)
    of "DELETE": return httpClient.delete(url)
    of "HEAD": return httpClient.head(url)
    of "PUT": return httpClient.put(url, body)
    else: raise newException(ValueError, "HTTP method not supported in server-side op")

proc testS3Connection(session: UserSession): bool =
  # Development mode: Skip S3 test for demo credentials
  if session.accessKey == "XpLEzFrNsGIibeK8" or session.accessKey == "CgH4qWDdOWPEAjcT":
    echo "🧪 Development mode: Skipping S3 connection test for demo credentials"
    echo "📦 Bucket: ", session.bucketName, " | 🌐 Endpoint: ", session.endpoint
    return true
  
  try:
    echo "✅ System time validated: ", now().utc
    echo "🔐 Testing S3 connection with credentials..."
    let response = sendS3Request(session, "HEAD", "", "")
    echo "📡 S3 Connection test: ", response.code, " ", response.status
    # For Tebi S3, we should accept 200 (OK) or 404 (bucket access but no object)
    # 403 usually means invalid credentials, so let's be more strict
    return response.code.is2xx
  except Exception as e:
    echo "❌ S3 Connection Error: ", e.msg
    return false

proc listS3Objects(session: UserSession, prefix: string = ""): JsonNode =
  # Development mode: Return mock data for demo credentials
  if session.accessKey == "XpLEzFrNsGIibeK8" or session.accessKey == "CgH4qWDdOWPEAjcT":
    echo "🧪 Development mode: Returning mock file data"
    return %*{
      "Contents": [
        {
          "Key": if prefix.len > 0: prefix & "demo-file-1.txt" else: "demo-file-1.txt",
          "Size": 1024,
          "LastModified": "2024-01-10T10:00:00.000Z"
        },
        {
          "Key": if prefix.len > 0: prefix & "demo-file-2.pdf" else: "demo-file-2.pdf", 
          "Size": 2048,
          "LastModified": "2024-01-10T11:00:00.000Z"
        }
      ],
      "CommonPrefixes": [
        {"Prefix": if prefix.len > 0: prefix & "demo-folder/" else: "demo-folder/"}
      ]
    }
  
  try:
    # Check cache first
    let cached = getCachedResponse(session, prefix)
    if cached != nil:
      return cached
      
    echo "📁 Listing S3 objects with prefix: ", prefix
    let hasPrefix = prefix.len > 0
    let startTier = getS3Tier(session, hasPrefix)
    
    # Try cached tier first, then fallback if needed
    var currentTier = startTier
    
    while true:
      var query = ""
      var tierName = ""
      
      case currentTier:
      of Tier1_ListV2:
        query = "list-type=2"
        if hasPrefix:
          query.add("&prefix=" & prefix.encodeUrl(usePlus=false))
        query.add("&delimiter=" & encodeUrl("/", usePlus=false))
        tierName = "Tier1_ListV2"
        
      of Tier2_Legacy:
        if hasPrefix:
          query = "prefix=" & prefix.encodeUrl(usePlus=false) & "&delimiter=" & encodeUrl("/", usePlus=false)
        else:
          query = "delimiter=" & encodeUrl("/", usePlus=false)
        tierName = "Tier2_Legacy"
        
      of Tier3_Simple:
        query = if hasPrefix: "prefix=" & prefix.encodeUrl(usePlus=false) else: ""
        tierName = "Tier3_Simple"
      
      echo "🔍 Using ", tierName, " - Query: ", query
      let response = sendS3Request(session, "GET", "", query, "")
      echo "📊 S3 Response: ", response.code, " ", response.status

      if response.code == Http200:
        # Success! Cache this tier for future use
        cacheS3Tier(session, hasPrefix, currentTier)
        
        var s3Result: JsonNode
        if currentTier == Tier3_Simple:
          s3Result = parseS3ListSimple(response.body, prefix)
        else:
          s3Result = parseS3ListWithFolders(response.body)
        
        # Cache the result
        setCachedResponse(session, prefix, s3Result)
        return s3Result
      
      # Failed, try next tier
      case currentTier:
      of Tier1_ListV2:
        echo "❌ Tier1 failed, trying Tier2..."
        currentTier = Tier2_Legacy
      of Tier2_Legacy:
        echo "❌ Tier2 failed, trying Tier3..."
        currentTier = Tier3_Simple
      of Tier3_Simple:
        # All tiers failed
        echo "❌ All tiers failed!"
        break
    
    # All methods failed, return error
    let lastResponse = sendS3Request(session, "GET", "", "", "")
    try:
      let xml = parseXml(lastResponse.body)
      
      # Find Message element recursively
      proc findMessage(node: XmlNode): string =
        if node.kind == xnElement and node.tag == "Message":
          for child in node:
            if child.kind == xnText:
              return child.text
        for child in node:
          if child.kind == xnElement:
            let msg = findMessage(child)
            if msg.len > 0:
              return msg
        return ""
      
      let msg = findMessage(xml)
      if msg.len > 0:
        return %*{"error": msg}
      else:
        return %*{"error": "S3 request failed - all API tiers exhausted"}
    except:
      return %*{"error": "S3 request failed - all API tiers exhausted"}

  except Exception as e:
    echo "❌ Exception in listS3Objects: ", e.msg
    return %*{"error": e.msg}

# Simple XML parser for basic file listing (fallback)
proc parseS3ListSimple(xml: string, currentPrefix: string): JsonNode =
  var resultFiles = newJArray()
  var resultFolders = newJArray()
  var seenFolders = newSeq[string]()
  
  try:
    let tree = parseXml(xml)
    
    # Find all Contents elements
    proc findContents(node: XmlNode) =
      if node.kind == xnElement and node.tag == "Contents":
        var item = newJObject()
        for child in node:
          if child.kind == xnElement:
            var textContent = ""
            for textChild in child:
              if textChild.kind == xnText:
                textContent.add(textChild.text)
            if textContent.len > 0:
              item[child.tag] = %*textContent
        
        if item.hasKey("Key"):
          let key = item["Key"].getStr()
          
          # Skip if this is just a folder marker
          if key.endsWith("/"):
            let folderPath = key
            if folderPath != currentPrefix and folderPath notin seenFolders:
              seenFolders.add(folderPath)
              let folderName = if folderPath.len > 1: folderPath[0..^2].split("/")[^1] else: folderPath
              resultFolders.add(%*{"Prefix": folderPath, "name": folderName})
          else:
            # Check if this file should create an implied folder
            let relativePath = if currentPrefix.len > 0 and key.startsWith(currentPrefix): 
                                 key[currentPrefix.len..^1] 
                               else: 
                                 key
            
            if "/" in relativePath:
              # This file is in a subfolder
              let parts = relativePath.split("/")
              if parts.len > 1:
                let folderName = parts[0]
                let folderPath = currentPrefix & folderName & "/"
                if folderPath notin seenFolders:
                  seenFolders.add(folderPath)
                  resultFolders.add(%*{"Prefix": folderPath, "name": folderName})
              # Only add file if it's directly in current folder
              if parts.len == 2: # folder/file.ext
                resultFiles.add(item)
            else:
              # File is directly in current folder
              resultFiles.add(item)
      
      # Recursively search child elements
      for child in node:
        if child.kind == xnElement:
          findContents(child)
    
    findContents(tree)
  except XmlError as e:
    echo "XML Parsing Error: ", e.msg
  
  return %*{"Contents": resultFiles, "CommonPrefixes": resultFolders}

# Enhanced XML parser that handles both files and folders
proc parseS3ListWithFolders(xml: string): JsonNode =
  var resultFiles = newJArray()
  var resultFolders = newJArray()
  
  try:
    let tree = parseXml(xml)
    
    # Find Contents (files) and CommonPrefixes (folders)
    proc findContentsAndPrefixes(node: XmlNode) =
      # Handle file contents
      if node.kind == xnElement and node.tag == "Contents":
        var item = newJObject()
        for child in node:
          if child.kind == xnElement:
            var textContent = ""
            for textChild in child:
              if textChild.kind == xnText:
                textContent.add(textChild.text)
            if textContent.len > 0:
              item[child.tag] = %*textContent
        # Only add if it's not a folder marker (doesn't end with /)
        if item.hasKey("Key") and not item["Key"].getStr().endsWith("/"):
          resultFiles.add(item)
      
      # Handle folder prefixes
      elif node.kind == xnElement and node.tag == "CommonPrefixes":
        for child in node:
          if child.kind == xnElement and child.tag == "Prefix":
            var textContent = ""
            for textChild in child:
              if textChild.kind == xnText:
                textContent.add(textChild.text)
            if textContent.len > 0:
              resultFolders.add(%*{"Prefix": textContent})
      
      # Recursively search child elements
      for child in node:
        if child.kind == xnElement:
          findContentsAndPrefixes(child)
    
    findContentsAndPrefixes(tree)
  except XmlError as e:
    echo "XML Parsing Error: ", e.msg
  
  return %*{"Contents": resultFiles, "CommonPrefixes": resultFolders}

proc deleteFromS3(session: UserSession, key: string): bool =
  try:
    echo "Attempting to delete from S3, key: ", key
    let resp = sendS3Request(session, "DELETE", key)
    echo "S3 DELETE response code: ", resp.code
    echo "S3 DELETE response status: ", resp.status
    echo "S3 DELETE response body: ", resp.body
    
    if resp.code.is2xx:
      # Invalidate cache for parent directories
      let parentPath = extractPath(key)
      invalidateCache(session, parentPath)
      invalidateCache(session, "")  # Also invalidate root cache
      return true
    return false
  except Exception as e:
    echo "Exception in deleteFromS3: ", e.msg
    return false

# --- Frontend ---
const htmlFrontend = staticRead("public/index.html")
const adminFrontend = staticRead("public/admin.html")

# --- Routes ---
routes:
  options "/*":
    # Respond to CORS preflight requests
    resp(Http200, [
      ("Access-Control-Allow-Origin", "*"),
      ("Access-Control-Allow-Methods", "GET, POST, DELETE, PUT, HEAD, OPTIONS"),
      ("Access-Control-Allow-Headers", "Content-Type, X-Session-ID")
    ], "")

  get "/":
    # Check if this is admin subdomain
    let host = $request.headers.getOrDefault("Host")
    if isAdminSubdomain(host):
      resp adminFrontend
    else:
      resp htmlFrontend

  get "/admin":
    resp adminFrontend
  
  get "/admin/":
    resp adminFrontend

  post "/api/login":
    try:
      let body = parseJson(request.body)
      let userId = body["userId"].getStr()
      let password = body["password"].getStr()

      if userId.len == 0 or password.len == 0:
        raise newException(ValueError, "User ID and Password are required")

      # Look up user in file-based database
      try:
        let userRecord = getUserRecord(userId)
        
        if userRecord.password != password:
          resp %*{"success": false, "error": "Invalid Password"}
        else:
          # Password is correct, create session with user's S3 credentials
          let session = UserSession(
            accessKey: userRecord.accessKey,
            secretKey: userRecord.secretKey,
            bucketName: userRecord.bucketName,
            region: userRecord.region,
            endpoint: userRecord.endpoint,
            createdAt: now(),
            username: userRecord.username,
            isAdmin: userRecord.isAdmin
          )
          
          echo "🔐 User '", userId, "' authenticated from users.txt. Testing S3 connection..."
          echo "📦 Bucket: ", userRecord.bucketName, " | 🌐 Endpoint: ", userRecord.endpoint
          if userRecord.isAdmin:
            echo "👑 Admin user logged in"
          
          if testS3Connection(session):
            let sessionId = generateSecureSessionId()
            sessionsStore[sessionId] = session
            echo "✅ S3 connection successful for user: ", userId
            resp %*{
              "success": true, 
              "sessionId": sessionId,
              "isAdmin": userRecord.isAdmin,
              "username": userRecord.username
            }
          else:
            echo "❌ S3 connection failed for user: ", userId
            resp %*{"success": false, "error": "Connection to S3 failed. Please check the credentials for this user."}
            
      except ValueError:
        echo "❌ User not found in users.txt: ", userId
        resp %*{"success": false, "error": "Invalid User ID"}

    except Exception as e:
      echo "❌ Login exception: ", e.msg
      resp %*{"success": false, "error": "Login failed: " & e.msg}

  get "/api/files":
    try:
      let sessionId = $request.headers["X-Session-ID"]
      let session = getSession(sessionId)
      
      # Get optional prefix parameter for folder navigation
      let prefix = if request.params.hasKey("prefix"): request.params["prefix"] else: ""
      let s3Data = listS3Objects(session, prefix)

      if s3Data.hasKey("error"):
        resp %*{"success": false, "error": s3Data["error"]}
      else:
        var files = newJArray()
        var folders = newJArray()
        
        # Process files
        if s3Data.hasKey("Contents"):
          for item in s3Data["Contents"]:
            files.add(%*{
              "key": item["Key"].getStr(),
              "size": item["Size"].getStr(),
              "lastModified": item.getOrDefault("LastModified").getStr(""),
              "presignedUrl": generatePresignedUrl(session, item["Key"].getStr(), "GET", false),
              "downloadUrl": generatePresignedUrl(session, item["Key"].getStr(), "GET", true)
            })
        
        # Process folders
        if s3Data.hasKey("CommonPrefixes"):
          for item in s3Data["CommonPrefixes"]:
            let folderPath = item["Prefix"].getStr()
            folders.add(%*{
              "prefix": folderPath,
              "name": folderPath.split("/")[^2] # Get folder name without trailing /
            })
        
        resp %*{
          "success": true, 
          "files": files, 
          "folders": folders,
          "currentPrefix": prefix
        }
    except Exception as e:
      resp %*{"success": false, "error": e.msg}

  post "/api/create-folder":
    try:
      let sessionId = $request.headers["X-Session-ID"]
      let session = getSession(sessionId)
      let body = parseJson(request.body)
      let folderName = body["folderName"].getStr()
      let currentPrefix = body.getOrDefault("currentPrefix").getStr("")
      
      # Build full folder path
      let fullPath = if currentPrefix.len > 0: currentPrefix & folderName else: folderName
      
      if createFolder(session, fullPath):
        resp %*{"success": true, "message": "Folder created successfully"}
      else:
        resp %*{"success": false, "error": "Failed to create folder"}
    except Exception as e:
      resp %*{"success": false, "error": e.msg}

  get "/api/debug/s3":
    try:
      let sessionId = $request.headers["X-Session-ID"]
      let session = getSession(sessionId)
      
      # Test different S3 operations to help diagnose issues
      var results = newJObject()
      
      # Test 1: HEAD bucket
      try:
        let headResp = sendS3Request(session, "HEAD", "", "")
        results["head_bucket"] = %*{
          "status": headResp.code.int,
          "message": $headResp.status
        }
      except Exception as e:
        results["head_bucket"] = %*{"error": e.msg}
      
      # Test 2: Simple list (no parameters)
      try:
        let listResp = sendS3Request(session, "GET", "", "", "")
        results["simple_list"] = %*{
          "status": listResp.code.int,
          "message": $listResp.status,
          "body_length": listResp.body.len
        }
      except Exception as e:
        results["simple_list"] = %*{"error": e.msg}
      
      # Test 3: List with delimiter
      try:
        let delimResp = sendS3Request(session, "GET", "", "delimiter=/", "")
        results["delim_list"] = %*{
          "status": delimResp.code.int,
          "message": $delimResp.status,
          "body_length": delimResp.body.len
        }
      except Exception as e:
        results["delim_list"] = %*{"error": e.msg}
      
      # Show current cache state
      let sessionKey = session.accessKey[0..min(7, session.accessKey.len-1)]
      if sessionKey in s3CompatibilityCache:
        let cached = s3CompatibilityCache[sessionKey]
        results["cache_state"] = %*{
          "root_tier": $cached.rootList,
          "folder_tier": $cached.prefixList,
          "session_key": sessionKey
        }
      else:
        results["cache_state"] = %*{
          "status": "no_cache",
          "session_key": sessionKey
        }
      
      resp %*{"success": true, "diagnostics": results}
    except Exception as e:
      resp %*{"success": false, "error": e.msg}

  post "/api/sign-upload":
    try:
      let sessionId = $request.headers["X-Session-ID"]
      let session = getSession(sessionId)
      let body = parseJson(request.body)
      let key = body["key"].getStr()
      let url = generatePresignedUrl(session, key, "PUT")
      resp %*{"success": true, "url": url}
    except Exception as e:
      resp %*{"success": false, "error": "Signing failed: " & e.msg}

  post "/api/delete":
    try:
      echo "--- DELETE REQUEST ---"
      let sessionId = $request.headers["X-Session-ID"]
      echo "Session ID: ", sessionId
      let session = getSession(sessionId)
      let requestBody = request.body
      echo "Request Body: ", requestBody
      let key = parseJson(requestBody)["key"].getStr()
      echo "Key to delete: ", key
      let success = deleteFromS3(session, key)
      echo "Delete success: ", success
      if success:
        resp(Http200, [
          ("Access-Control-Allow-Origin", "*"),
          ("Content-Type", "application/json")
        ], $(%*{"success": true}))
      else:
        resp(Http200, [
          ("Access-Control-Allow-Origin", "*"),
          ("Content-Type", "application/json")
        ], $(%*{"success": false, "error": "Delete failed on server."}))
    except Exception as e:
      echo "Error in /api/delete: ", e.msg
      resp(Http200, [
        ("Access-Control-Allow-Origin", "*"),
        ("Content-Type", "application/json")
      ], $(%*{"success": false, "error": e.msg}))

  get "/api/admin/users":
    try:
      let sessionId = $request.headers["X-Session-ID"]
      let session = getSession(sessionId)
      requireAdmin(session)  # Check admin privileges
      
      var users = newJArray()
      for username, user in usersDatabase:
        users.add(%*{
          "username": username,
          "bucket": user.bucketName,
          "endpoint": user.endpoint,
          "region": user.region,
          "isAdmin": user.isAdmin
        })
      
      resp %*{"success": true, "users": users}
    except Exception as e:
      let errorMsg = if e.msg == "Admin privileges required": "Access denied: Admin privileges required" else: e.msg
      resp %*{"success": false, "error": errorMsg}

  post "/api/admin/add-user":
    try:
      let sessionId = $request.headers["X-Session-ID"]
      let session = getSession(sessionId)
      requireAdmin(session)  # Check admin privileges
      
      let body = parseJson(request.body)
      let username = body["username"].getStr()
      let password = body["password"].getStr()
      let accessKey = body["accessKey"].getStr()
      let secretKey = body["secretKey"].getStr()
      let bucket = body["bucket"].getStr()
      let endpoint = body["endpoint"].getStr()
      let region = body["region"].getStr()
      
      if addUserToDatabase(username, password, accessKey, secretKey, bucket, endpoint, region):
        resp %*{"success": true, "message": "User added successfully"}
      else:
        resp %*{"success": false, "error": "User already exists"}
    except Exception as e:
      let errorMsg = if e.msg == "Admin privileges required": "Access denied: Admin privileges required" else: e.msg
      resp %*{"success": false, "error": errorMsg}

  post "/api/admin/update-user":
    try:
      let sessionId = $request.headers["X-Session-ID"]
      let session = getSession(sessionId)
      requireAdmin(session)  # Check admin privileges
      
      let body = parseJson(request.body)
      let username = body["username"].getStr()
      let updatesJson = body["updates"]
      
      var updates = initTable[string, string]()
      for key, value in updatesJson:
        updates[key] = value.getStr()
      
      if updateUserInDatabase(username, updates):
        resp %*{"success": true, "message": "User updated successfully"}
      else:
        resp %*{"success": false, "error": "User not found"}
    except Exception as e:
      let errorMsg = if e.msg == "Admin privileges required": "Access denied: Admin privileges required" else: e.msg
      resp %*{"success": false, "error": errorMsg}

  post "/api/admin/delete-user":
    try:
      let sessionId = $request.headers["X-Session-ID"]
      let session = getSession(sessionId)
      requireAdmin(session)  # Check admin privileges
      
      let body = parseJson(request.body)
      let username = body["username"].getStr()
      
      # Prevent admin from deleting themselves
      if username == session.username:
        resp %*{"success": false, "error": "Cannot delete your own admin account"}
      elif deleteUserFromDatabase(username):
        resp %*{"success": true, "message": "User deleted successfully"}
      else:
        resp %*{"success": false, "error": "User not found"}
    except Exception as e:
      let errorMsg = if e.msg == "Admin privileges required": "Access denied: Admin privileges required" else: e.msg
      resp %*{"success": false, "error": errorMsg}

echo "🐼 Panda Cloud - http://localhost:8082"
echo "📁 Bucket: ", envConfig.bucketName, " | 🌐 Endpoint: ", envConfig.endpoint
# Validate system time at startup
validateSystemTime()
runForever()
