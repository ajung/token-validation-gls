import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.text.ParseException;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IdTokenTokenValidationTest {

    IdTokenTokenValidation cut = new IdTokenTokenValidation();

    @Test
    void validate() throws MalformedURLException, ParseException {
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJYUDRkUXFXM21kdUFGVHZRWHN3Q2pUc3FhTW1XcVIxRHBtUDg3RUZ6Zk00In0.eyJleHAiOjE2MTc4MTE1MjIsImlhdCI6MTYxNzgxMTIyMiwianRpIjoiYTU1NjUwNDctZDAxYy00NDQxLWIyNTUtZGRiODQyNGU2Y2RkIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLWRldi5kYy5nbHMtZ3JvdXAuZXUvYXV0aC9yZWFsbXMvZ2xzIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6Ijk0ZjZiYjZmLTQ0NDEtNGY1YS1iYzEwLWQ0NDcyMDFiMzQ3MCIsInR5cCI6IkJlYXJlciIsImF6cCI6ImN1c3RvbWVyLXBvcnRhbC1xYSIsInNlc3Npb25fc3RhdGUiOiJiMmI0ZGUzZS05N2VkLTQ5YzgtODFjMy1lMTYxYzI0MjkzZGUiLCJhY3IiOiIxIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIHJvbGVzIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJyb2xhbmQud2ViZXIudGVzdCIsInVzZXJfbm8iOiIyMTkwNzE5In0.gG-nZ_pyv0Ehnkw-9K6t_CDUNh6Y3UHWStydQ3B3fPscdzNlYReFf6p-_k4k-_3TGTWhJuL_43RcVAmvfCd8ousSTqITgd6kDvlXvI6juMFVIBSm-QIE2fpl0mteXTXfEquijT9M7iClBitZsQaD3vH-20DKPw6DFMbMAH8uWl4Q5LbsCpsX2q0Y-MhegxLH80agNBuEktQ8J-TRJRaWoZdQbH66htham8fFKZWZK5AxIaqdZ-ecbPSWZbDRAg1ir5sUgrhdnT_t6KHueYJseoC9MhjCI4VHlYxh_WaAoSK88U6aht2MFVL_MmFvf_WfruGWeAErpgS3f-8Ems3NGg";

        Boolean result  =  cut.validate(token);
        assertTrue(result);

    }
}