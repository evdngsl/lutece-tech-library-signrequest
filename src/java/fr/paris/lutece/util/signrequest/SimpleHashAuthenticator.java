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

import fr.paris.lutece.util.signrequest.security.HashService;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpMethodBase;

/**
 * SimpleHashAuthenticator
 */
public class SimpleHashAuthenticator implements RequestAuthenticator
{
    private static final String HEADER_SIGNATURE = "Lutece Request Signature";
    private static final String HEADER_TIMESTAMP = "Lutece Request Timestamp";
    
    private List<String> _listSignatureElements;
    private static HashService _serviceHash;
    private String _strPrivateKey;
    
    /**
     * Sets the list of signature elements
     * @param list The list
     */
    public void setSignatureElements( List<String> list )
    {
        _listSignatureElements = list;
    }
    
    /**
     * Sets the Hash service
     * @param service The Hash service
     */
    public void setHashService( HashService service )
    {
        _serviceHash = service;
    }
    
    /**
     * Sets the private key
     * @param strKey The private key
     */
    public void setPrivateKey( String strKey )
    {
        _strPrivateKey = strKey;
    }
    
    /**
     * {@inheritDoc }
     */
    public boolean isRequestAuthenticated( HttpServletRequest request )
    {
        String strHash1 = request.getHeader( HEADER_SIGNATURE );
        String strTimestamp = request.getHeader( HEADER_TIMESTAMP );
        
        // no signature or timestamp
        if( ( strHash1 == null ) || ( strTimestamp == null ) )
        {
            return false;
        }
        
        if( isValidTimestamp( strTimestamp ))
        {
            
        }
        
        List<String> listElements = new ArrayList<String>();
        for( String strParameter : _listSignatureElements )
        {
            String strValue = request.getParameter( strParameter );
            if( strValue != null )
            {
                listElements.add( strValue );
            }
        }
        
        String strHash2 = buildSignature( listElements , strTimestamp );
        return strHash1.equals( strHash2 );
       
    }
    
    /**
     * {@inheritDoc }
     */
    public void authenticateRequest( HttpMethodBase method , List<String> elements )
    {
        String strTimestamp = "" + new Date().getTime();
        Header header = new Header( HEADER_TIMESTAMP , strTimestamp );
        method.setRequestHeader( header );

        String strSignature = buildSignature( elements , strTimestamp );
        header = new Header( HEADER_SIGNATURE , strSignature );
        method.setRequestHeader( header );
        
    }
    
    /**
     * Create a signature  
     * @param listElements The list of elements that part of the hash 
     * @return A signature as an Hexadecimal Hash
     */
    private String buildSignature( List<String> listElements , String strTimestamp )
    {
        StringBuilder sb = new StringBuilder();
        for( String strElement : listElements )
        {
            sb.append( strElement );
        }
        
        sb.append( _strPrivateKey );
        sb.append( strTimestamp );
        return _serviceHash.getHash( sb.toString() );
    }

    /**
     * This method can be overriden to check the date of the request
     * @param strTimestamp The timestamp
     * @return true if the timestamp is valid, otherwise false
     */
    protected boolean isValidTimestamp( String strTimestamp  )
    {
        return true;
    }
    
}
