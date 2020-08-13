<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1" session="false"%>
<!DOCTYPE html>
<% 
	HttpSession session = request.getSession(false);
	if(session == null) {
		response.sendRedirect("index.html"); 
	}
	
%>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Success!</title>
</head>
<body>
blah
</body>
</html>