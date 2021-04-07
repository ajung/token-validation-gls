import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;

import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;

public class AccessTokenValidation {
    public boolean validate(String tokenString) throws MalformedURLException, ParseException {
        Issuer iss = new Issuer("https://auth-dev.dc.gls-group.eu/auth/realms/gls");
        ClientID clientID = new ClientID("account");
        JWSAlgorithm jwsAlg = JWSAlgorithm.RS256;
        URL jwkSetURL = new URL("https://auth-dev.dc.gls-group.eu/auth/realms/gls/protocol/openid-connect/certs");
        IDTokenValidator validator = new IDTokenValidator(iss, clientID, jwsAlg, jwkSetURL);
        JWT idToken = JWTParser.parse(tokenString);
        try {
            validator.validate(idToken, null);
            return true;
        } catch (BadJOSEException e) {
            return false;
        } catch (JOSEException e) {
            return false;
        }
    }
}
