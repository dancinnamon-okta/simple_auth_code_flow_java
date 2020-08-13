<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1" session="true" %>

<!DOCTYPE html>
<% 
	
	if(session.getAttribute("jwt_user") == null) {
		response.sendRedirect("index.html"); 
	}
	
%>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Success!</title>
</head>
<body>
	<%
		out.print(session.getAttribute("jwt_user").toString());
	%>
</body>
</html>