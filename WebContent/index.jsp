<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1" session="true" %>
<!DOCTYPE html>
<html>
  <head>
    <!-- Okta Widget -->
    <script src="https://global.oktacdn.com/okta-signin-widget/3.4.0/js/okta-sign-in.min.js" type="text/javascript"></script>
    <link href="https://global.oktacdn.com/okta-signin-widget/3.4.0/css/okta-sign-in.min.css" type="text/css" rel="stylesheet"/>
  </head>
  <body>
    <div id="okta-login-container"></div>
    <script>
      var okta_org = '<%= pageContext.getServletContext().getInitParameter("okta_org") %>';
      var okta_client_id = '<%= pageContext.getServletContext().getInitParameter("client_id") %>';
      var issuer = '<%= pageContext.getServletContext().getInitParameter("jwt_issuer") %>';
      var redirect_uri = '<%= pageContext.getServletContext().getInitParameter("redirect_uri") %>'

      var auth_params = {
        issuer: issuer,
        responseType: ['code'],
        scopes: ['openid', 'email', 'profile'],
      }

      var oktaSignIn = new OktaSignIn({
        baseUrl: okta_org,
        clientId: okta_client_id,
        redirectUri: redirect_uri,
        authParams: auth_params
      });

      oktaSignIn.authClient.session.exists()
      .then(function(exists) {
        if (exists) {
          // logged in
          oktaSignIn.authClient.token.getWithRedirect(auth_params)
        } else {
          // not logged in
          oktaSignIn.renderEl({el: '#okta-login-container'});
        }
      });
    </script>

  </body>
</html>