

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.okta.jwt.AccessTokenVerifier;
import com.okta.jwt.Jwt;
import com.okta.jwt.JwtVerificationException;
import com.okta.jwt.JwtVerifiers;

/**
 * Servlet implementation class OIDCCallback
 */
@WebServlet("/oidc-callback")
public class OIDCCallback extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public OIDCCallback() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		String authCode = request.getParameter("code");
		ServletConfig sc=getServletConfig();
		
		String client_id = sc.getInitParameter("client_id");
		String client_secret = sc.getInitParameter("client_secret");
		String token_endpoint = sc.getInitParameter("token_endpoint");
		String jwt_issuer = sc.getInitParameter("jwt_issuer");
		String jwt_audience = sc.getInitParameter("jwt_audience");
		
		//We require an OAuth2 authorization code. If we don't have it, we're done.
		if(authCode != null) {
			//Compile our /token request.
			String reqContent = "client_id=%s&client_secret=%s&code=%s&grant_type=authorization_code&redirect_uri=%s";
			String body = String.format(reqContent,
					client_id,
					client_secret,
					authCode,
					"http://localhost:8080/simple_auth_code_flow_java/oidc-callback");

			HttpClient client = HttpClient.newHttpClient();
			HttpRequest req = HttpRequest.newBuilder()
					.uri(URI.create(token_endpoint))
					.POST(BodyPublishers.ofString(body))
					.header("Content-Type", "application/x-www-form-urlencoded")
					.build();

			HttpResponse<String> resp;
			try {
				//Post to the /token endpoint to get our token.
				resp = client.send(req, BodyHandlers.ofString());
				
				//The body contains several things- one of them is the access token we want.
				Map<String,String> result =
				        new ObjectMapper().readValue(resp.body(), HashMap.class);
				AccessTokenVerifier jwtVerifier = JwtVerifiers.accessTokenVerifierBuilder()
						.setIssuer(jwt_issuer)
						.setAudience(jwt_audience)				
					    .setConnectionTimeout(Duration.ofSeconds(1)) // defaults to 1s
					    .setReadTimeout(Duration.ofSeconds(1))       // defaults to 1s
					    .build();
				
				Jwt jwt = jwtVerifier.decode(result.get("access_token"));
				
				//Now that we're logged in, let's add to our session variable.
				//Here is where you'd do all the normal things you're used to doing when logging a user in.
				HttpSession session=request.getSession();
			    session.setAttribute("jwt_user", jwt.getClaims().get("sub").toString());
			    response.sendRedirect("profile.jsp");

			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (JwtVerificationException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		else {
			response.sendError(400, "Bad Request - this endpoint expects an OAuth2 authoriztion code, but none was provided.");
		}
	}

}
