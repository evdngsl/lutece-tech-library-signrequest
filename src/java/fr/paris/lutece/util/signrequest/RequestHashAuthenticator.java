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

import org.apache.commons.httpclient.HttpMethodBase;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;


/**
 * RequestHashAuthenticator
 */
public class RequestHashAuthenticator extends AbstractAuthenticator implements RequestAuthenticator
{
    private static final String PARAMETER_SIGNATURE = "signature";
    private static final String PARAMETER_TIMESTAMP = "timestamp";

    /**
     * {@inheritDoc }
     */
    public boolean isRequestAuthenticated( HttpServletRequest request )
    {
        String strHash1 = request.getParameter( PARAMETER_SIGNATURE );
        String strTimestamp = request.getParameter( PARAMETER_TIMESTAMP );

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
        String strQueryString = method.getQueryString(  );
        String strTimestamp = "" + new Date(  ).getTime(  );
        strQueryString += ( "&" + PARAMETER_TIMESTAMP + "=" + strTimestamp );

        String strSignature = buildSignature( elements, strTimestamp );
        strQueryString += ( "&" + PARAMETER_SIGNATURE + "=" + strSignature );

        method.setQueryString( strQueryString );
    }

    public String addExtrasUrlParameters( String url, List<String> elements )
    {
        StringBuilder sbExtrasParameters = new StringBuilder(  );

        if ( url.contains( "=" ) )
        {
            sbExtrasParameters.append( url ).append( "&" );
        }
        else
        {
            sbExtrasParameters.append( url ).append( "?" );
        }

        String strTimestamp = "" + new Date(  ).getTime(  );
        sbExtrasParameters.append( PARAMETER_TIMESTAMP ).append( "=" ).append( strTimestamp );

        String strSignature = buildSignature( elements, strTimestamp );
        sbExtrasParameters.append( "&" ).append( PARAMETER_SIGNATURE ).append( "=" ).append( strSignature );

        return sbExtrasParameters.toString(  );
    }

    /**
     * Add security parameters to a parameter map
     * @param mapParameters The parameter map
     * @param elements The element list to build the signature
     */
    public void addSecurityParameters( Map mapParameters, List<String> elements )
    {
        String strTimestamp = "" + new Date(  ).getTime(  );
        mapParameters.put( PARAMETER_TIMESTAMP, strTimestamp );

        String strSignature = buildSignature( elements, strTimestamp );
        mapParameters.put( PARAMETER_SIGNATURE, strSignature );
    }
}
