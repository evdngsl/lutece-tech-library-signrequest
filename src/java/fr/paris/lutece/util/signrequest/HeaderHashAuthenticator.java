/*
 * Copyright (c) 2002-2011, Mairie de Paris
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

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpMethodBase;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.servlet.http.HttpServletRequest;


/**
 * HeaderHashAuthenticator
 */
public class HeaderHashAuthenticator extends AbstractAuthenticator implements RequestAuthenticator
{
    private static final String HEADER_SIGNATURE = "Lutece Request Signature";
    private static final String HEADER_TIMESTAMP = "Lutece Request Timestamp";

    /**
     * {@inheritDoc }
     */
    public boolean isRequestAuthenticated( HttpServletRequest request )
    {
        String strHash1 = request.getHeader( HEADER_SIGNATURE );
        String strTimestamp = request.getHeader( HEADER_TIMESTAMP );

        // no signature or timestamp
        if ( ( strHash1 == null ) || ( strTimestamp == null ) )
        {
            _logger.info( "SignRequest - Invalid signature" );

            return false;
        }

        if ( !isValidTimestamp( strTimestamp ) )
        {
            _logger.info( "SignRequest - Invalid timestamp : " + strTimestamp );

            return false;
        }

        List<String> listElements = new ArrayList<String>(  );

        for ( String strParameter : getSignatureElements(  ) )
        {
            String strValue = request.getParameter( strParameter );

            if ( strValue != null )
            {
                listElements.add( strValue );
            }
        }

        String strHash2 = buildSignature( listElements, strTimestamp );

        return strHash1.equals( strHash2 );
    }

    /**
     * {@inheritDoc }
     */
    public void authenticateRequest( HttpMethodBase method, List<String> elements )
    {
        String strTimestamp = "" + new Date(  ).getTime(  );
        Header header = new Header( HEADER_TIMESTAMP, strTimestamp );
        method.setRequestHeader( header );

        String strSignature = buildSignature( elements, strTimestamp );
        header = new Header( HEADER_SIGNATURE, strSignature );
        method.setRequestHeader( header );
    }
}