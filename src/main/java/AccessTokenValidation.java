import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.source.*;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.*;
import com.nimbusds.jwt.proc.*;
import net.minidev.json.JSONObject;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashSet;

public class AccessTokenValidation {

    public JSONObject validate(String accessToken ) throws MalformedURLException, BadJOSEException, ParseException, JOSEException {

        ConfigurableJWTProcessor<SecurityContext> jwtProcessor =
                new DefaultJWTProcessor<>();
        JWKSource<SecurityContext> keySource =
                new RemoteJWKSet<>(new URL("https://auth-qs.dc.gls-group.eu/auth/realms/gls/protocol/openid-connect/certs"));
        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;
        JWSKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);
        jwtProcessor.setJWSKeySelector(keySelector);

        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(
                new JWTClaimsSet.Builder().issuer("https://auth-qs.dc.gls-group.eu/auth/realms/gls").build(),
                new HashSet<>(Arrays.asList("sub"))));
        JWTClaimsSet claimsSet = jwtProcessor.process(accessToken, null);
        return claimsSet.toJSONObject();
    }
}
