/*
 * Copyright (c) 2002-2016, Mairie de Paris
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice
 *     and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice
 *     and the following disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 *  3. Neither the name of 'Mairie de Paris' nor 'Lutece' nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * License 1.0
 */

package fr.paris.lutece.util.signrequest;

import fr.paris.lutece.test.MokeHttpServletRequest;
import fr.paris.lutece.util.jwt.service.JWTUtil;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import static org.junit.Assert.*;
import org.junit.Test;

/**
 * JWTSecretKeyAuthenticatorTest
 */
public class JWTRSAPlainTextAuthenticatorTest
{
    private static final String CLAIM_KEY = "claim_key";
    private static final String CLAIM_VALUE = "claim_value";
    private static final String HTTP_HEADER_NAME = "header_name";
    private static final String ALGO = "RS256";
    private static final long VALIDITY = 60000;
    private static final String PUB_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCUp/oV1vWc8/TkQSiAvTousMzOM4asB2iltr2QKozni5aVFu818MpOLZIr8LMnTzWllJvvaA5RAAdpbECb+48FjbBe0hseUdN5HpwvnH/DW8ZccGvk53I6Orq7hLCv1ZHtuOCokghz/ATrhyPq+QktMfXnRS4HrKGJTzxaCcU7OQIDAQAB";
    private static final String PRIV_KEY = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJSn+hXW9Zzz9ORBKIC9Oi6wzM4zhqwHaKW2vZAqjOeLlpUW7zXwyk4tkivwsydPNaWUm+9oDlEAB2lsQJv7jwWNsF7SGx5R03kenC+cf8Nbxlxwa+Tncjo6uruEsK/Vke244KiSCHP8BOuHI+r5CS0x9edFLgesoYlPPFoJxTs5AgMBAAECgYBL/6iiO7hr2mjrvMgZMSSqtCawkLUcA9mjRs6ZArfwtHNymzwGZqj22ONu5WqiASPbGCO0fI09KfegFQDe/fe6wnpirBWtawLoXCZmGrwC+x/3iqbiGJMd7UB3FaZkZOzV5Jhzomc8inSJWMcR+ywiUY37stfVDqR1sJ/jzZ1OdQJBAO8vCa2OVQBJbzjMvk8Sc0KiuVwnyqMYqVty6vYuufe9ILJfhwhYzE82wIa9LYg7UK2bPvKyyehuFfqI5oU5lU8CQQCfG5LA3gp3D1mS7xxztqJ+cm4SPO4R6YzVybAZKqKUvTFSKNV57Kp/LL7WjtUUNr+dY+aYRlKo81Hq61y8tBT3AkAjJyak+2ZCxIg0MONHe8603HWhtbdygQ1jA2DFDdkHMCS+EowmDeb5PXLOWr92ZkFVQpvdz6kdIBDa4YP/0JbBAkBVHLjqd1z9x7ZRBZwgwkg2gBwloXZxGpB+JMARFl+WVYa2vqVD7bhfA56qxAl0IL1sAm7ucl/xhQgDNRiM0YCNAkEAqySTBx2HO9VyzuWWbf7BYTNsxfO80GaRkZGENfqO1QgnhT1FMeK+ox7Kbi+nSaCBoPjNzyrMbU08M6nSnkDEGA==";

    /**
     * Test of isRequestAuthenticated method, of class JWTRSAPlainTextAuthenticatorTest.
     * @throws java.security.spec.InvalidKeySpecException
     * @throws java.security.NoSuchAlgorithmException
     */
    @Test
    public void testSignRequestAndTestAuth( ) throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        MokeHttpServletRequest request = new MokeHttpServletRequest( );

        Map<String, String> mapJWTClaims = new HashMap<>( );
        mapJWTClaims.put( CLAIM_KEY, CLAIM_VALUE );

        JWTRSAPlainTextAuthenticator authenticator = new JWTRSAPlainTextAuthenticator( mapJWTClaims, HTTP_HEADER_NAME, VALIDITY, ALGO, PRIV_KEY, PUB_KEY );
        
        KeyFactory kf = KeyFactory.getInstance( "RSA" );
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode( PRIV_KEY ) );
        PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);

        //Build a request with a JWT in header
        request.addMokeHeader( HTTP_HEADER_NAME, JWTUtil.buildBase64JWT( mapJWTClaims, authenticator.getExpirationDate( ), ALGO, privKey ) );

        assertTrue( authenticator.isRequestAuthenticated( request ) );
        assertTrue( JWTUtil.checkPayloadValues( request, HTTP_HEADER_NAME, mapJWTClaims ) );
    }
}
