

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
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
	@SuppressWarnings("unchecked")
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		String authCode = request.getParameter("code");

		String client_id = getServletContext().getInitParameter("client_id");
		String client_secret = getServletContext().getInitParameter("client_secret");
		String jwt_issuer = getServletContext().getInitParameter("jwt_issuer");
		String jwt_audience = getServletContext().getInitParameter("jwt_audience");
		String redirect_uri = getServletContext().getInitParameter("redirect_uri");

		//A very important step in the OAuth2 flow is validating the state parameter! e.g CSRF!
		validateState(request);

		//We require an OAuth2 authorization code. If we don't have it, we're done.
		if(authCode != null) {
			//Compile our /token request.
			String reqContent = "client_id=%s&client_secret=%s&code=%s&grant_type=authorization_code&redirect_uri=%s";
			String body = String.format(reqContent,
					client_id,
					client_secret,
					authCode,
					redirect_uri);
			String tokenUrl = jwt_issuer + "/v1/token";
			
			try {

				//String tokenResponseBody = sendTokenRequestJava11Plus(tokenUrl, body);
				String tokenResponseBody = sendTokenRequestPreJava11(tokenUrl, body);

				//The body contains several things- one of them is the access token we want.
				Map<String,String> result =
				        new ObjectMapper().readValue(tokenResponseBody, HashMap.class);
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

			//} catch (InterruptedException e) {
				// TODO Auto-generated catch block
			//	e.printStackTrace();
			} catch (JwtVerificationException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		else {
			response.sendError(400, "Bad Request - this endpoint expects an OAuth2 authoriztion code, but none was provided.");
		}
	}
	private void validateState(HttpServletRequest request) {
		Cookie[] cookies = request.getCookies();
		String sentState = "";

		//Get the state from the okta-oauth-state cookie.  Okta's SDK does this automatically when the
		//authorize request is sent.
		for (int i = 0; i < cookies.length; i++) {
			if (cookies[i].getName() == "okta-oauth-state") {
				sentState = cookies[i].getValue();
			}
		}

		//Get the state passed in the querystring back from the authorization server.
		String receivedState = request.getParameter("state");

		// Protect against CSRF.
		assert(sentState.length() > 0);
		assert(receivedState != null);
		assert(sentState == receivedState);
	}
	
	/*The token request will be easier to make in Java 11+ where the HttpClient library is introduced.
	/*
	 * private String sendTokenRequestJava11Plus(String tokenUrl, String reqBody)
	 * throws IOException, InterruptedException { HttpClient client =
	 * HttpClient.newHttpClient(); HttpRequest req = HttpRequest.newBuilder()
	 * .uri(URI.create(tokenUrl)) .POST(BodyPublishers.ofString(reqBody))
	 * .header("Content-Type", "application/x-www-form-urlencoded") .build();
	 * 
	 * HttpResponse<String> resp;
	 * 
	 * //Post to the /token endpoint to get our token. resp = client.send(req,
	 * BodyHandlers.ofString()); return resp.body(); }
	 */
	
	//Use older libraries to make the OAuth2 /token request to Okta.
	private String sendTokenRequestPreJava11(String tokenUrl, String reqBody) throws IOException {
		URL url = new URL(tokenUrl);
		HttpURLConnection con = (HttpURLConnection)url.openConnection();
		StringBuilder tokenResponse;
		con.setRequestMethod("POST");
		con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
		con.setRequestProperty("Accept", "application/json");
		con.setDoOutput(true);

		//Send POST request to Okta.
		try(OutputStream os = con.getOutputStream()) {
		    byte[] input = reqBody.getBytes("utf-8");
		    os.write(input, 0, input.length);			
		}
		
		//Read the token response.
		try(BufferedReader br = new BufferedReader(
				new InputStreamReader(con.getInputStream(), "utf-8"))) {
					tokenResponse = new StringBuilder();
				    String responseLine = null;
				    while ((responseLine = br.readLine()) != null) {
				    	tokenResponse.append(responseLine.trim());
				    }
				}
		return tokenResponse.toString();
	}
}
