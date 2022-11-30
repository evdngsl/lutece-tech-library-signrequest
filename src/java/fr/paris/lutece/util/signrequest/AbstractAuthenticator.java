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

import java.util.Date;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import fr.paris.lutece.util.signrequest.security.HashService;

/**
 * AbstractAuthenticator
 */
public abstract class AbstractAuthenticator implements RequestAuthenticator
{
    protected static final Logger LOGGER = LogManager.getLogger( "lutece.security.signrequest" );
    private static HashService _serviceHash;
    private List<String> _listSignatureElements;
    protected long _lValidityTimePeriod;

    /**
     * Sets the list of signature elements
     * 
     * @param list
     *            The list
     */
    public void setSignatureElements( List<String> list )
    {
        _listSignatureElements = list;
    }

    /**
     * Returns the list of signature elements
     * 
     * @return The list of elements
     */
    protected List<String> getSignatureElements( )
    {
        return _listSignatureElements;
    }

    /**
     * Sets the Hash service
     * 
     * @param service
     *            The Hash service
     */
    public void setHashService( HashService service )
    {
        _serviceHash = service;
    }

    /**
     * Sets validity time period (in seconds) between the timestamp in the request and the server timestamp
     * 
     * @param lPeriod
     *            The validity time period
     */
    public void setValidityTimePeriod( long lPeriod )
    {
        _lValidityTimePeriod = lPeriod;
    }

    /**
     * Get validity time period (in seconds) between the timestamp in the request and the server timestamp
     * 
     * @return the validity time period
     */
    public long getValidityTimePeriod( )
    {
        return _lValidityTimePeriod;
    }

    /**
     * Create a signature
     * 
     * @param listElements
     *            The list of elements that part of the hash
     * @param strTimestamp
     *            The timestamp
     * @param strSecret
     *            The secret
     * @return A signature as an Hexadecimal Hash
     */
    public String buildSignature( List<String> listElements, String strTimestamp, String strSecret )
    {
        StringBuilder sbSignature = new StringBuilder( );

        if ( listElements != null )
        {
            for ( String strElement : listElements )
            {
                sbSignature.append( strElement );
            }
        }

        sbSignature.append( strSecret ).append( strTimestamp );

        return _serviceHash.getHash( sbSignature.toString( ) );
    }

    /**
     * This method checks the date of the request
     * 
     * @param strTimestamp
     *            The timestamp
     * @return true if the timestamp is valid, otherwise false
     */
    protected boolean isValidTimestamp( String strTimestamp )
    {
        if ( _lValidityTimePeriod != 0L )
        {
            try
            {
                long lTimeRequest = Long.parseLong( strTimestamp );
                long lTimeCurrent = new Date( ).getTime( );
                boolean bValid = ( ( ( lTimeCurrent - lTimeRequest ) / 1000L ) < _lValidityTimePeriod );

                if ( !bValid )
                {
                    LOGGER.info( "SignRequest - Timestamp expired : " + strTimestamp );
                }

                return bValid;
            }
            catch( NumberFormatException e )
            {
                // Invalid Timestamp
                LOGGER.error( "SignRequest - Invalid timestamp : " + strTimestamp );

                return false;
            }
        }

        // Period = 0 no check
        return true;
    }
}
