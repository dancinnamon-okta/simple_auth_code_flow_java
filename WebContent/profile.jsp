<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1" session="true" %>

<!DOCTYPE html>
<% 
	//Really, really basic "am i logged in?" logic.
	if(session.getAttribute("jwt_user") == null) {
		response.sendRedirect("index.jsp"); 
	}
	
%>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Success!</title>
</head>
<body>
<h1>Welcome,
<%
	out.print(session.getAttribute("jwt_user").toString());
%>
</h1>
</body>
</html>