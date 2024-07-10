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

import java.util.Base64;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;



/**
 * BasicAuthorizationAuthenticator.<br>
 * This authenticator provides a basic username/password authentication.<br>
 * The request should have a header named Authorization with a value that begins with "Basic" followed by the "username:password" encoded in base64.
 */
public class BasicAuthorizationAuthenticator extends AbstractAuthenticator
{

    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String BASIC_AUTHORIZATION_PREFIX = "Basic ";
    private final String _strUsername;
    private final String _strPassword;

    /**
     * Constructor that define credentials
     *
     * @param strUsername
     *            The username
     * @param strPassword
     *            The password
     */
    public BasicAuthorizationAuthenticator( String strUsername, String strPassword )
    {
        super( );
        _strUsername = strUsername;
        _strPassword = strPassword;
    }

    /**
     * {@inheritDoc }
     */
    @Override
    public boolean isRequestAuthenticated( HttpServletRequest request )
    {
        String strHeader = request.getHeader( HEADER_AUTHORIZATION );
        int nPos = strHeader.indexOf( BASIC_AUTHORIZATION_PREFIX );
        if ( nPos == 0 )
        {
            String strDigest = strHeader.substring( BASIC_AUTHORIZATION_PREFIX.length( ) );
            return strDigest.equals( getDigest( ) );
        }
        return false;
    }

    /**
     * {@inheritDoc }
     */
    @Override
    public AuthenticateRequestInformations  getSecurityInformations( List<String> elements )
    {
        String strHeader = BASIC_AUTHORIZATION_PREFIX + getDigest( );
        
        return new AuthenticateRequestInformations().addSecurityHeader(HEADER_AUTHORIZATION, strHeader );  
      
    }

    /**
     * Build the digest
     *
     * @return The digest
     */
    private String getDigest( )
    {
        String strSecret = _strUsername + ':' + _strPassword;
        byte [ ] encodedBytes = Base64.getEncoder().encode( strSecret.getBytes() );

        return new String( encodedBytes );
    }

}
