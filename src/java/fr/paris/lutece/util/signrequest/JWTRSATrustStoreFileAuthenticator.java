/*
 * Copyright (c) 2002-2021, City of Paris
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

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.HttpMethodBase;

public class JWTRSATrustStoreFileAuthenticator extends AbstractJWTRSAAuthenticator
{
    private final String _strCacertPath;
    private final String _strCacertPassword;
    private final String _strAlias;

    /**
     * Constructor
     * 
     * @param mapClaimsToCheck
     *            The map of claims key/values to check in the JWT
     * @param strJWTHttpHeader
     *            The name of the header which contains the JWT
     * @param lValidityPeriod
     *            The validity period
     * @param strEncryptionAlgorythmName
     *            The name of the algorithm.
     * @param strCacertPath
     * @param strCacertPassword
     * @param strAlias
     */
    public JWTRSATrustStoreFileAuthenticator( Map<String, String> mapClaimsToCheck, String strJWTHttpHeader, long lValidityPeriod,
            String strEncryptionAlgorythmName, String strCacertPath, String strCacertPassword, String strAlias )
    {
        super( mapClaimsToCheck, strJWTHttpHeader, lValidityPeriod, strEncryptionAlgorythmName );
        _strCacertPath = strCacertPath;
        _strCacertPassword = strCacertPassword;
        _strAlias = strAlias;
    }

    /**
     * {@inheritDoc }
     */
    @Override
    protected KeyPair getKeyPair( )
    {
        try
        {
            FileInputStream is = new FileInputStream( _strCacertPath );
            KeyStore keystore = KeyStore.getInstance( KeyStore.getDefaultType( ) );
            keystore.load( is, _strCacertPassword.toCharArray( ) );
            Certificate cert = keystore.getCertificate( _strAlias );
            PublicKey publicKey = cert.getPublicKey( );

            return new KeyPair( publicKey, null );
        }

        catch( CertificateException | IOException | KeyStoreException | NoSuchAlgorithmException e )
        {
            LOGGER.error( "Unable to get key pair from certificate", e );
        }

        return null;
    }

    /**
     * {@inheritDoc }
     */
    @Override
    public void authenticateRequest( HttpMethodBase method, List<String> elements )
    {
        // Do nothing : its not possible to authenticate a request only with a trustore file, because its
        // it only contains public key. Use a JWTCertificateFileAuthenticator if you
        // want to sign request with RSA private key.
    }
}
